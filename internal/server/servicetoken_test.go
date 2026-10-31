package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/aenix-io/aeman/internal/forge"
	"github.com/aenix-io/aeman/pkg/gitstore"
)

// G82 — service tokens: a non-interactive caller (an agent's account, a
// bot) presents `Authorization: Bearer aeman_svc_…` on /api/v1 and /mcp
// and acts as the login its line in AEMAN_SERVICE_TOKENS_FILE names. The
// server holds only the SHA-256 of each token; the rights are decided the
// way a person's are — by the forge, asked with the server's credential,
// or by the line's groups through the OIDC access rules — and its commits
// are authored with its login.

const (
	botToken  = "aeman_svc_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	readToken = "aeman_svc_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func writeTokens(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// touch moves a file's modification time on, the way a rewritten Secret
// mount does, so a rewrite of the same size is still a change.
func touch(t *testing.T, path string, d time.Duration) {
	t.Helper()
	at := time.Now().Add(d)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func asService(t *testing.T, srv *Server, token, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, r)
	return rec
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

// The file is a line per token: login, the hex SHA-256 of the token, and —
// in the OIDC mode only — groups=<g1,g2>. Blank lines and # comments are
// skipped. Anything else is refused whole, with the line number: a typo
// must not quietly turn a token off (or on).
func TestParseServiceTokens(t *testing.T) {
	h1, h2 := tokenHash(botToken), tokenHash(readToken)
	entries, err := parseServiceTokens([]byte("# agents\n\nbot " + h1 + "\n  reader   " + strings.ToUpper(h2) + "  groups=devs,ops \n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].login != "bot" || entries[1].login != "reader" ||
		!slices.Equal(entries[1].groups, []string{"devs", "ops"}) || entries[0].groups != nil {
		t.Fatalf("entries = %+v", entries)
	}
	if hex.EncodeToString(entries[1].hash[:]) != h2 {
		t.Fatal("an upper-case hash is the same hash")
	}
	for name, bad := range map[string]string{
		"no hash":        "bot\n",
		"short hash":     "bot abc123\n",
		"not hex":        "bot " + strings.Repeat("z", 64) + "\n",
		"unknown field":  "bot " + h1 + " admin=true\n",
		"empty groups":   "bot " + h1 + " groups=\n",
		"a token itself": "bot " + botToken + "\n",
		"same hash":      "bot " + h1 + "\nother " + h1 + "\n",
		"twice groups":   "bot " + h1 + " groups=a groups=b\n",
	} {
		if _, err := parseServiceTokens([]byte(bad)); err == nil {
			t.Errorf("%s: %q was accepted", name, bad)
		}
	}
}

// A token is known by its hash, compared in constant time; a token without
// the aeman_svc_ prefix is never one, whatever its hash.
func TestServiceTokenLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\nplain "+tokenHash("no-prefix")+"\n")
	st, err := openServiceTokens(path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if acct, ok := st.lookup(botToken); !ok || acct.login != "bot" {
		t.Fatalf("lookup(bot) = %+v %v", acct, ok)
	}
	for _, tok := range []string{readToken, "no-prefix", "", "aeman_svc_"} {
		if acct, ok := st.lookup(tok); ok {
			t.Errorf("lookup(%q) = %+v; want unknown", tok, acct)
		}
	}
}

// The file is re-read when it changes: a line added works on the next
// request, a line removed stops working on the next request, and a file
// broken by an edit admits nobody until it is fixed — the token someone was
// in the middle of revoking must not keep working because of a typo. A file
// that cannot be read at start is a start-up error.
func TestServiceTokensFileIsReReadWhenItChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\n")
	st, err := openServiceTokens(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.lookup(readToken); ok {
		t.Fatal("reader is not in the file yet")
	}
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\nreader "+tokenHash(readToken)+"\n")
	touch(t, path, time.Second)
	if acct, ok := st.lookup(readToken); !ok || acct.login != "reader" {
		t.Fatalf("a line added is live on the next request: %+v %v", acct, ok)
	}
	writeTokens(t, path, "reader "+tokenHash(readToken)+"\n")
	touch(t, path, 2*time.Second)
	if _, ok := st.lookup(botToken); ok {
		t.Fatal("a line removed must stop working on the next request")
	}
	writeTokens(t, path, "reader "+tokenHash(readToken)+"\noops\n")
	touch(t, path, 3*time.Second)
	if _, ok := st.lookup(readToken); ok {
		t.Fatal("a broken file admits nobody")
	}
	writeTokens(t, path, "reader "+tokenHash(readToken)+"\n")
	touch(t, path, 4*time.Second)
	if _, ok := st.lookup(readToken); !ok {
		t.Fatal("the fixed file admits again")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.lookup(readToken); ok {
		t.Fatal("a removed file admits nobody")
	}
	if _, err := openServiceTokens(filepath.Join(t.TempDir(), "missing"), true, nil); err == nil {
		t.Fatal("a file that is not there at start must be refused")
	}
}

// Groups mean something only where the OIDC access rules read them; on a
// forge-mode server a line with groups is refused rather than ignored.
func TestServiceTokenGroupsNeedOIDC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+" groups=devs\n")
	if _, err := openServiceTokens(path, false, nil); err == nil || !strings.Contains(err.Error(), "groups") {
		t.Fatalf("groups on a forge-mode server: %v; want a refusal naming groups", err)
	}
	if _, err := openServiceTokens(path, true, nil); err != nil {
		t.Fatalf("groups on an OIDC server: %v", err)
	}
}

// Service tokens are for a multi-user server: the single-user server has
// no sign-in for them to stand beside.
func TestServiceTokensNeedTheMultiUserMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\n")
	_, err := New(Options{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ServiceTokensFile: path,
	})
	if err == nil {
		t.Fatal("a single-user server with service tokens must be refused")
	}
}

// fakePermissions is a GitHub that answers only the collaborator
// permission, asked with the server token "srv-token": login → domain
// (the repository name's suffix) → permission.
func fakePermissions(t *testing.T, perms map[string]map[string]string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		i := strings.Index(r.URL.Path, "/collaborators/")
		if i < 0 || !strings.HasSuffix(r.URL.Path, "/permission") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer srv-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		repo := r.URL.Path[:i]
		login := strings.TrimSuffix(r.URL.Path[i+len("/collaborators/"):], "/permission")
		for domain, p := range perms[login] {
			if strings.HasSuffix(repo, "-"+domain) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"permission":"` + p + `"}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(gh.Close)
	return gh
}

// forgeServiceServer is a forge-OAuth server over shared (primary) and
// closed, whose forge is the fake above and whose service tokens are the
// file at path.
func forgeServiceServer(t *testing.T, gh *httptest.Server, path string) *Server {
	t.Helper()
	shared, closed := gitRemoteOwned(t, "shared"), gitRemoteOwned(t, "closed")
	seedGitRemote(t, shared)
	seedClosedRemote(t, closed)
	srv, err := New(Options{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Forge:             forge.NewGitHubAt(gh.URL),
		Auth:              &OAuthConfig{ClientID: "gh-client", ClientSecret: "gh-secret", BaseURL: testBaseURL},
		ServiceTokensFile: path,
		Git: &GitConfig{Repos: []RepoSpec{{Name: "shared", URL: shared.URL}, {Name: "closed", URL: closed.URL}},
			Token: "srv-token", DataDir: t.TempDir(), Committer: gitstore.Identity{Name: "aeman", Email: "aeman@test"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	srv.gitBE.git.pushDelay = 0
	srv.handler = conforms(t, srv.handler)
	return srv
}

// gitRemoteOwned is gitRemoteN under an owner, so the forge names it
// owner/repo the way it names a real repository.
func gitRemoteOwned(t *testing.T, name string) gitstore.Remote {
	t.Helper()
	url := "gittest://remotes/acme/" + strings.ReplaceAll(t.Name(), "/", "_") + "-" + name + ".git"
	gitTestRemotes[url] = memory.NewStorage()
	return gitstore.Remote{URL: url}
}

const newCardBody = `{"title":"from the agent","team":"portal","zone":"planned","dates":{"start":"2026-08-27"}}`

// createdBy creates a card as the service token and returns the commit
// that landed it.
func createdBy(t *testing.T, srv *Server, token string) (uid string, author, actor string) {
	t.Helper()
	rec := asService(t, srv, token, http.MethodPost, "/api/v1/views/team/cards", newCardBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /cards with a service token: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Metadata struct{ UID string } `json:"metadata"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.store.waitDrained(ctx)
	repo := srv.gitBE.git.primary()
	c, err := repo.CommitObject(repo.Head())
	if err != nil {
		t.Fatal(err)
	}
	return created.Metadata.UID, c.Author.Name, gitstore.ParseTrailers(c.Message).Actor
}

// G82 — forge mode: the server's own credential asks the forge what the
// token's login may do with each domain. A writer creates a card, and the
// commit is authored with its login; a reader reads and is refused the
// write; an unknown token is 401 notAuthenticated, and so is one whose line
// was taken out of the file — at once, with no restart.
func TestServiceTokenInForgeMode(t *testing.T) {
	var calls atomic.Int32
	gh := fakePermissions(t, map[string]map[string]string{
		"bot":    {"shared": "write", "closed": "read"},
		"reader": {"shared": "read"},
	}, &calls)
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\nreader "+tokenHash(readToken)+"\n")
	srv := forgeServiceServer(t, gh, path)

	uid, author, actor := createdBy(t, srv, botToken)
	if author != "bot" || actor != "bot" {
		t.Fatalf("the commit is %q with actor %q; want both the token's login, bot", author, actor)
	}
	if rec := asService(t, srv, botToken, http.MethodGet, "/api/v1/views/all/cards", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), uid) || !strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("bot reads both domains: %d %s", rec.Code, rec.Body.String())
	}
	r, err := srv.serviceRights(context.Background(), serviceAccount{login: "bot"})
	if err != nil || !r.canWrite("shared") || !r.canRead("closed") || r.canWrite("closed") {
		t.Fatalf("bot's rights = %+v, %v; want write shared, read closed", r, err)
	}

	rec := asService(t, srv, readToken, http.MethodGet, "/api/v1/views/all/cards", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), uid) || strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("reader reads shared and not closed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := asService(t, srv, readToken, http.MethodPost, "/api/v1/views/team/cards", newCardBody); rec.Code != http.StatusForbidden {
		t.Fatalf("a reader's write: %d %s, want 403", rec.Code, rec.Body.String())
	}

	if rec := asService(t, srv, "aeman_svc_unknown", http.MethodGet, "/api/v1/board", ""); rec.Code != http.StatusUnauthorized || problemCode(t, rec) != "notAuthenticated" {
		t.Fatalf("an unknown token: %d %s, want 401 notAuthenticated", rec.Code, rec.Body.String())
	}

	writeTokens(t, path, "reader "+tokenHash(readToken)+"\n")
	touch(t, path, time.Second)
	if rec := asService(t, srv, botToken, http.MethodGet, "/api/v1/board", ""); rec.Code != http.StatusUnauthorized || problemCode(t, rec) != "notAuthenticated" {
		t.Fatalf("a removed token: %d %s, want 401 notAuthenticated", rec.Code, rec.Body.String())
	}
}

// G82 — the forge's answer for a service login is cached for accessTTL like
// a person's, so an agent's burst of calls asks the forge once per domain.
func TestServiceTokenRightsAreCachedForTheTTL(t *testing.T) {
	var calls atomic.Int32
	gh := fakePermissions(t, map[string]map[string]string{"bot": {"shared": "write"}}, &calls)
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\n")
	srv := forgeServiceServer(t, gh, path)
	calls.Store(0)
	for range 3 {
		if rec := asService(t, srv, botToken, http.MethodGet, "/api/v1/board", ""); rec.Code != http.StatusOK {
			t.Fatalf("GET /board: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("%d forge calls for three requests, want one per domain", n)
	}
}

// G82 — OIDC mode: the line's groups go through the same --oidc-access
// rules as a person's. A devs token writes shared and cannot see closed; an
// auditors token reads everywhere and writes nowhere; a token whose groups
// open no domain is refused like a person with no readable domain.
func TestServiceTokenInOIDCMode(t *testing.T) {
	idp := newFakeIdP(t)
	path := filepath.Join(t.TempDir(), "tokens")
	const noneToken = "aeman_svc_00000000000000000000000000000000000000000000000000000000deadbeef"
	writeTokens(t, path, "bot "+tokenHash(botToken)+" groups=devs\n"+
		"audit "+tokenHash(readToken)+" groups=auditors\n"+
		"stray "+tokenHash(noneToken)+" groups=marketing\n")
	shared, closed := gitRemoteN(t, "shared"), gitRemoteN(t, "closed")
	seedGitRemote(t, shared)
	seedClosedRemote(t, closed)
	srv, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: &OAuthConfig{
			ClientID: oidcClientID, ClientSecret: oidcClientSecret, BaseURL: testBaseURL,
			OIDC: &OIDCConfig{Issuer: idp.srv.URL, Name: "Corp SSO", Access: teamRules},
		},
		ServiceTokensFile: path,
		Git: &GitConfig{Repos: []RepoSpec{{Name: "shared", URL: shared.URL}, {Name: "closed", URL: closed.URL}},
			DataDir: t.TempDir(), Committer: gitstore.Identity{Name: "aeman", Email: "aeman@test"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	srv.gitBE.git.pushDelay = 0
	srv.handler = conforms(t, srv.handler)

	_, author, _ := createdBy(t, srv, botToken)
	if author != "bot" {
		t.Fatalf("commit author = %q, want bot", author)
	}
	if rec := asService(t, srv, botToken, http.MethodGet, "/api/v1/views/all/cards", ""); strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("devs do not read closed: %s", rec.Body.String())
	}
	if rec := asService(t, srv, readToken, http.MethodGet, "/api/v1/views/all/cards", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("auditors read every domain: %d %s", rec.Code, rec.Body.String())
	}
	if rec := asService(t, srv, readToken, http.MethodPost, "/api/v1/views/team/cards", newCardBody); rec.Code != http.StatusForbidden {
		t.Fatalf("an auditor's write: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := asService(t, srv, noneToken, http.MethodGet, "/api/v1/board", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a token no rule opens a domain to: %d %s, want 403", rec.Code, rec.Body.String())
	}
	// The provider is never asked about a service login: its groups are the
	// line's.
	idp.mu.Lock()
	asked := idp.userinfoCalls
	idp.mu.Unlock()
	if asked != 0 {
		t.Fatalf("the provider was asked %d times about a service token", asked)
	}
}

// G82 — the MCP path: the bearer middleware takes a service token as it
// takes an MCP session, the tool call acts as the token's login with the
// rights decided for it, and an unknown service token is refused there too.
func TestServiceTokenOnMCP(t *testing.T) {
	var calls atomic.Int32
	gh := fakePermissions(t, map[string]map[string]string{"bot": {"shared": "write"}}, &calls)
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\n")
	srv := forgeServiceServer(t, gh, path)

	info, err := srv.auth.verifyToken(context.Background(), botToken, nil)
	if err != nil || info.UserID != "bot" || info.Expiration.IsZero() {
		t.Fatalf("verifyToken(service) = %+v, %v", info, err)
	}
	if _, err := srv.auth.verifyToken(context.Background(), "aeman_svc_unknown", nil); err == nil {
		t.Fatal("an unknown service token must not verify")
	}

	mcpCall := func(sessionID, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+botToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			r.Header.Set("Mcp-Session-Id", sessionID)
		}
		rec := httptest.NewRecorder()
		srv.handler.ServeHTTP(rec, r)
		return rec
	}
	rec := mcpCall("", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}`)
	sid := rec.Header().Get("Mcp-Session-Id")
	if rec.Code != http.StatusOK || sid == "" {
		t.Fatalf("initialize with a service token: %d %s", rec.Code, rec.Body.String())
	}
	if n := mcpCall(sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); n.Code/100 != 2 {
		t.Fatalf("initialized: %d %s (init %s)", n.Code, n.Body.String(), rec.Body.String())
	}
	before := srv.gitBE.git.primary().Head()
	rec = mcpCall(sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_card","arguments":{"view":"team","team":"portal","title":"from mcp","zone":"planned"}}}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Fatalf("create_card over MCP: %d %s", rec.Code, rec.Body.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.store.waitDrained(ctx)
	repo := srv.gitBE.git.primary()
	commits := commitsSince(t, repo, before)
	if len(commits) == 0 || commits[0].Author.Name != "bot" {
		t.Fatalf("the MCP card's commit: %d commits, want one authored by bot", len(commits))
	}

	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer aeman_svc_unknown")
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	srv.handler.ServeHTTP(out, r)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown service token on /mcp: %d, want 401", out.Code)
	}
}
