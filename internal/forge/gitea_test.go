package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitea is enough of a Gitea (or Forgejo — the same API v1) for the
// adapter: who-am-i, a repository's permissions block as each visitor sees
// it, the collaborator permission endpoint the server token asks, and the
// user directory. It is mounted under a subpath, the way a Gitea behind a
// reverse proxy often is, so a base URL with a path is the case exercised.
func fakeGitea(t *testing.T) *httptest.Server {
	t.Helper()
	users := map[string]map[string]string{
		"alice-token": {"login": "alice", "full_name": "Alice Liddell", "avatar_url": "https://gitea.example/avatars/alice"},
		"bob-token":   {"login": "bob", "full_name": "Bob", "avatar_url": "https://gitea.example/avatars/bob"},
	}
	// Who may do what on team/board, as each token sees it.
	perms := map[string]map[string]bool{
		"alice-token": {"admin": true, "push": true, "pull": true},
		"bob-token":   {"admin": false, "push": false, "pull": true},
	}
	// The collaborator permission each login holds on team/board.
	roles := map[string]string{"alice": "owner", "bob": "read", "carol": "none", "dave": "admin", "erin": "write"}
	mux := http.NewServeMux()
	auth := func(r *http.Request) string {
		return strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
	}
	mux.HandleFunc("/git/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		u, ok := users[auth(r)]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(u)
	})
	mux.HandleFunc("/git/api/v1/repos/team/board", func(w http.ResponseWriter, r *http.Request) {
		tok := auth(r)
		if tok == "expired-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		p, ok := perms[tok]
		if !ok {
			// Gitea hides a private repository from a stranger behind a 404.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "team/board", "private": true, "permissions": p})
	})
	mux.HandleFunc("/git/api/v1/repos/team/notes", func(w http.ResponseWriter, _ *http.Request) {
		// A public repository: anyone reads it, nobody here pushes.
		_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "team/notes", "private": false,
			"permissions": map[string]bool{"admin": false, "push": false, "pull": true}})
	})
	mux.HandleFunc("/git/api/v1/repos/team/board/collaborators/", func(w http.ResponseWriter, r *http.Request) {
		if auth(r) != "server-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		login := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/git/api/v1/repos/team/board/collaborators/"), "/permission")
		role, ok := roles[login]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"permission": role, "role_name": role,
			"user": map[string]string{"login": login, "full_name": strings.ToUpper(login[:1]) + login[1:], "avatar_url": "https://gitea.example/avatars/" + login}})
	})
	mux.HandleFunc("/git/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		login := strings.TrimPrefix(r.URL.Path, "/git/api/v1/users/")
		if login != "carol" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "carol", "full_name": "Carol", "avatar_url": "https://gitea.example/avatars/carol"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Gitea and Forgejo are one adapter: Forgejo keeps the Gitea API v1. The
// forge is named by the host — one that says gitea, forgejo or codeberg —
// or by --forge gitea / forgejo, or by a Gitea base URL; the label follows
// what the operator or the host called it, so a Forgejo board does not tell
// its visitors to sign in with Gitea.
func TestDetectNamesGiteaAndForgejo(t *testing.T) {
	cases := []struct {
		url, explicit, giteaBase string
		label, host, authorize   string
	}{
		{"https://gitea.example.org/team/board.git", "", "", "Gitea", "gitea.example.org", "https://gitea.example.org/login/oauth/authorize"},
		{"https://codeberg.org/team/board.git", "", "", "Forgejo", "codeberg.org", "https://codeberg.org/login/oauth/authorize"},
		{"https://forgejo.example.org/team/board.git", "", "", "Forgejo", "forgejo.example.org", "https://forgejo.example.org/login/oauth/authorize"},
		{"https://git.example.org/team/board.git", "gitea", "", "Gitea", "git.example.org", "https://git.example.org/login/oauth/authorize"},
		{"https://git.example.org/team/board.git", "forgejo", "", "Forgejo", "git.example.org", "https://git.example.org/login/oauth/authorize"},
		// A base URL with a subpath: the endpoints hang off it, the host is the key.
		{"https://git.example.org/git/team/board.git", "", "https://git.example.org/git/", "Gitea", "git.example.org", "https://git.example.org/git/login/oauth/authorize"},
		{"", "gitea", "https://Git.Example.org", "Gitea", "git.example.org", "https://Git.Example.org/login/oauth/authorize"},
	}
	for _, tc := range cases {
		f, err := DetectBases(tc.url, Kind(tc.explicit), Bases{Gitea: tc.giteaBase})
		if err != nil {
			t.Fatalf("DetectBases(%q, %q, %q): %v", tc.url, tc.explicit, tc.giteaBase, err)
		}
		if f.Kind() != Gitea || f.Label() != tc.label || f.Host() != tc.host || f.AuthorizeURL() != tc.authorize {
			t.Errorf("DetectBases(%q, %q, %q) = %s %q %q %q; want gitea %q %q %q", tc.url, tc.explicit, tc.giteaBase,
				f.Kind(), f.Label(), f.Host(), f.AuthorizeURL(), tc.label, tc.host, tc.authorize)
		}
	}

	// The hosts that name another forge keep it; an explicit kind still wins.
	for _, tc := range []struct {
		url, explicit string
		want          Kind
	}{
		{"https://github.com/acme/board.git", "", GitHub},
		{"https://gitlab.example.org/a/b.git", "", GitLab},
		{"https://gitea.example.org/a/b.git", "github", GitHub},
	} {
		f, err := DetectBases(tc.url, Kind(tc.explicit), Bases{})
		if err != nil || f.Kind() != tc.want {
			t.Errorf("DetectBases(%q, %q) = %v, %v; want %s", tc.url, tc.explicit, f, err, tc.want)
		}
	}

	// Gitea with nowhere to live is refused, not guessed.
	if _, err := DetectBases("", Gitea, Bases{}); err == nil {
		t.Fatal("--forge gitea with neither a repository nor --gitea-url must be refused")
	}
	// Two self-hosted bases and a host that names neither: the operator has
	// to say which forge the board is on.
	if _, err := DetectBases("https://git.example.org/a/b.git", "", Bases{GitLab: "https://git.example.org", Gitea: "https://git.example.org"}); err == nil {
		t.Fatal("both --gitlab-url and --gitea-url without --forge must be refused")
	}
	// Detect, the GitLab-only form, is unchanged by the third forge.
	if f, err := Detect("https://git.example.org/a/b.git", "", "https://git.example.org"); err != nil || f.Kind() != GitLab {
		t.Fatalf("Detect with a GitLab base = %v, %v; want GitLab", f, err)
	}
}

// The OAuth endpoints are Gitea's /login/oauth pair under the base URL; the
// default scopes read the user and the repositories — a visitor's token
// never pushes, the server's own credential does.
func TestGiteaOAuthEndpointsAndForms(t *testing.T) {
	g := NewGitea("https://gitea.example.org/", "Gitea")
	if g.AuthorizeURL() != "https://gitea.example.org/login/oauth/authorize" || g.TokenURL() != "https://gitea.example.org/login/oauth/access_token" {
		t.Fatalf("endpoints = %s %s", g.AuthorizeURL(), g.TokenURL())
	}
	if g.DefaultScopes() != "read:user read:repository" {
		t.Fatalf("scopes = %q", g.DefaultScopes())
	}
	ex := g.ExchangeForm("id", "secret", "code-1", "https://board.example/auth/callback")
	if ex.Get("grant_type") != "authorization_code" || ex.Get("redirect_uri") != "https://board.example/auth/callback" ||
		ex.Get("code") != "code-1" || ex.Get("client_id") != "id" || ex.Get("client_secret") != "secret" {
		t.Fatalf("exchange form = %v", ex)
	}
	rf := g.RefreshForm("id", "secret", "refresh-1", "https://board.example/auth/callback")
	if rf.Get("grant_type") != "refresh_token" || rf.Get("refresh_token") != "refresh-1" || rf.Get("client_id") != "id" || rf.Get("client_secret") != "secret" {
		t.Fatalf("refresh form = %v", rf)
	}
	if a := g.GitAuth("tok"); a.Password != "tok" || a.Username == "" {
		t.Fatalf("git auth = %+v; want the token as the password of a non-empty user", a)
	}
}

// A repository on Gitea is always owner/name, whatever subpath the
// instance is mounted at; anything shorter names no repository.
func TestGiteaRepoRefIsOwnerAndName(t *testing.T) {
	g := NewGitea("https://git.example.org/git", "Gitea")
	for url, want := range map[string]string{
		"https://git.example.org/git/team/board.git": "team/board",
		"https://gitea.example.org/team/board":       "team/board",
		"git@gitea.example.org:team/board.git":       "team/board",
		"team/board":                                 "team/board",
	} {
		if got, err := g.RepoRef(url); err != nil || got != want {
			t.Errorf("RepoRef(%q) = %q, %v; want %q", url, got, err, want)
		}
	}
	if _, err := g.RepoRef("https://gitea.example.org/board.git"); err == nil {
		t.Fatal("a URL with no owner names no repository")
	}
}

func TestGiteaUserIsTheTokensOwnerWithNameAndAvatar(t *testing.T) {
	srv := fakeGitea(t)
	g := NewGitea(srv.URL+"/git", "Gitea")
	u, err := g.User(context.Background(), guardedClient(srv), "alice-token")
	if err != nil || u.Login != "alice" || u.Name != "Alice Liddell" || u.AvatarURL != "https://gitea.example/avatars/alice" {
		t.Fatalf("User = %+v, %v", u, err)
	}
	if _, err := g.User(context.Background(), guardedClient(srv), "expired-token"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a rejected token = %v, want ErrBadToken", err)
	}
}

// Access on Gitea is the repository's permissions block as the visitor sees
// it: pull reads, push writes. A private repository the visitor cannot see
// is a 404 — no access, not an error; a rejected token is ErrBadToken; a
// public repository reads for anyone.
func TestGiteaAccessReadsThePermissionsBlock(t *testing.T) {
	srv := fakeGitea(t)
	g := NewGitea(srv.URL+"/git", "Gitea")
	ctx := context.Background()
	repo := srv.URL + "/git/team/board.git"
	for name, tc := range map[string]struct {
		token       string
		read, write bool
	}{
		"owner":    {"alice-token", true, true},
		"reader":   {"bob-token", true, false},
		"stranger": {"stranger-token", false, false},
	} {
		read, write, err := g.Access(ctx, guardedClient(srv), tc.token, repo)
		if err != nil || read != tc.read || write != tc.write {
			t.Errorf("%s: Access = %v %v %v; want %v %v", name, read, write, err, tc.read, tc.write)
		}
	}
	if _, _, err := g.Access(ctx, guardedClient(srv), "expired-token", repo); !errors.Is(err, ErrBadToken) {
		t.Fatalf("expired token: %v, want ErrBadToken", err)
	}
	if read, write, err := g.Access(ctx, guardedClient(srv), "bob-token", srv.URL+"/git/team/notes.git"); err != nil || !read || write {
		t.Fatalf("public repository: %v %v %v; want read only", read, write, err)
	}
}

// Readers on Gitea asks each login's collaborator permission with the
// server's credential — org teams and ownership included, as Gitea computes
// it — and keeps whoever reads: "none" does not, an unknown login is
// skipped. The answer carries the user, so names and avatars come with it.
func TestGiteaReadersAreThoseWithAtLeastReadPermission(t *testing.T) {
	srv := fakeGitea(t)
	g := NewGitea(srv.URL+"/git", "Gitea")
	repo := srv.URL + "/git/team/board.git"
	got, err := g.Readers(context.Background(), guardedClient(srv), "server-token", repo, []string{"alice", "bob", "carol", "nobody"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["alice"].Name != "Alice" || got["bob"].AvatarURL != "https://gitea.example/avatars/bob" {
		t.Fatalf("readers = %+v; want alice and bob with their names and avatars", got)
	}
	if _, err := g.Readers(context.Background(), guardedClient(srv), "", repo, []string{"alice"}); err == nil {
		t.Fatal("without a server token there is nobody to ask the forge as")
	}
	if _, err := g.Readers(context.Background(), guardedClient(srv), "bob-token", repo, []string{"alice"}); err == nil {
		t.Fatal("a server token the forge refuses is an error, not an empty board")
	}
}

// Permission is how a service token's login has its rights decided: the
// server's credential asks the same collaborator permission Readers asks,
// which Gitea computes from ownership, collaboration and org teams alike.
// owner, admin and write push; read reads; none and a login the forge does
// not know are neither. A server credential the forge refuses is an error —
// never ErrBadToken, which would end the visitor's own session.
func TestGiteaPermissionIsAskedWithTheServerCredential(t *testing.T) {
	srv := fakeGitea(t)
	g := NewGitea(srv.URL+"/git", "Gitea")
	repo := srv.URL + "/git/team/board.git"
	for login, want := range map[string][2]bool{
		"alice":  {true, true},   // owner
		"dave":   {true, true},   // admin
		"erin":   {true, true},   // write
		"bob":    {true, false},  // read
		"carol":  {false, false}, // none
		"nobody": {false, false}, // 404: not a login the forge knows
	} {
		read, write, err := g.Permission(context.Background(), guardedClient(srv), "server-token", repo, login)
		if err != nil || read != want[0] || write != want[1] {
			t.Errorf("Permission(%s) = %v %v %v; want %v %v", login, read, write, err, want[0], want[1])
		}
	}
	if _, _, err := g.Permission(context.Background(), guardedClient(srv), "bob-token", repo, "alice"); err == nil || errors.Is(err, ErrBadToken) {
		t.Errorf("a refused server credential = %v; want an error that is not ErrBadToken", err)
	}
	if _, _, err := g.Permission(context.Background(), guardedClient(srv), "", repo, "alice"); err == nil {
		t.Error("without a server credential there is nobody to ask the forge as")
	}
}

// Lookup asks the user directory: an avatar on Gitea is served by the
// instance, there is no URL to build from the login.
func TestGiteaLookupAsksTheUserDirectory(t *testing.T) {
	srv := fakeGitea(t)
	g := NewGitea(srv.URL+"/git", "Gitea")
	p, err := g.Lookup(context.Background(), guardedClient(srv), "", "carol")
	if err != nil || p.Login != "carol" || p.Name != "Carol" || p.AvatarURL != "https://gitea.example/avatars/carol" {
		t.Fatalf("Lookup(carol) = %+v, %v", p, err)
	}
	if _, err := g.Lookup(context.Background(), guardedClient(srv), "", "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup(nobody) = %v, want ErrNotFound", err)
	}
}

// Throttling on Gitea is a 429; it is never read as "no access".
func TestGiteaThrottlingIsNotNoAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	g := NewGitea(srv.URL, "Gitea")
	if _, _, err := g.Access(context.Background(), guardedClient(srv), "tok", srv.URL+"/team/board.git"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Access while throttled = %v, want ErrRateLimited", err)
	}
	if _, err := g.Readers(context.Background(), guardedClient(srv), "tok", srv.URL+"/team/board.git", []string{"a"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Readers while throttled = %v, want ErrRateLimited", err)
	}
	if _, _, err := g.Permission(context.Background(), guardedClient(srv), "tok", srv.URL+"/team/board.git", "a"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Permission while throttled = %v, want ErrRateLimited", err)
	}
}
