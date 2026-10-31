package main

import (
	"context"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aenix-io/aeman/internal/forge"
)

// A board on Gitea or Forgejo is named the way a GitLab one is: by the
// primary repository's host (one that says gitea, forgejo or codeberg), by
// --forge gitea|forgejo / AEMAN_FORGE, or by --gitea-url / AEMAN_GITEA_URL
// for an instance whose host says nothing. The label follows the name, so
// a Forgejo board's copy says Forgejo.
func TestGitConfigNamesGiteaAndForgejo(t *testing.T) {
	cases := []struct {
		args      []string
		env       map[string]string
		label     string
		authorize string
	}{
		{[]string{"--repo", "https://gitea.example.org/team/board.git"}, nil, "Gitea", "https://gitea.example.org/login/oauth/authorize"},
		{[]string{"--repo", "https://codeberg.org/team/board.git"}, nil, "Forgejo", "https://codeberg.org/login/oauth/authorize"},
		{[]string{"--repo", "https://git.example.org/team/board.git", "--forge", "forgejo"}, nil, "Forgejo", "https://git.example.org/login/oauth/authorize"},
		{[]string{"--repo", "https://git.example.org/team/board.git"}, map[string]string{"AEMAN_FORGE": "gitea"}, "Gitea", "https://git.example.org/login/oauth/authorize"},
		{[]string{"--repo", "https://git.example.org/git/team/board.git", "--gitea-url", "https://git.example.org/git"}, nil, "Gitea", "https://git.example.org/git/login/oauth/authorize"},
		{[]string{"--repo", "https://git.example.org/team/board.git"}, map[string]string{"AEMAN_GITEA_URL": "https://git.example.org"}, "Gitea", "https://git.example.org/login/oauth/authorize"},
	}
	for _, tc := range cases {
		cfg := parseGitFlags(t, tc.env, tc.args)
		if cfg.Forge.Kind() != forge.Gitea || cfg.Forge.Label() != tc.label || cfg.Forge.AuthorizeURL() != tc.authorize {
			t.Errorf("%v %v: forge = %s %q %q, want gitea %q %q", tc.args, tc.env,
				cfg.Forge.Kind(), cfg.Forge.Label(), cfg.Forge.AuthorizeURL(), tc.label, tc.authorize)
		}
	}

	// Both self-hosted bases and a host that names neither: refused, the
	// operator says which forge with --forge.
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	gf := addGitFlags(fs, func(string) string { return "" })
	if err := fs.Parse([]string{"--repo", "https://git.example.org/a/b.git", "--gitlab-url", "https://git.example.org", "--gitea-url", "https://git.example.org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := gf.config(); err == nil || !strings.Contains(err.Error(), "--forge") {
		t.Fatalf("two self-hosted bases without --forge: %v", err)
	}
}

// A unit carries the resolved Gitea instance and its name: a Forgejo at a
// subpath of a host that says neither must come back as that Forgejo.
func TestFlagArgsCarryTheGiteaInstance(t *testing.T) {
	want := parseGitFlags(t, map[string]string{
		"AEMAN_REPOS":     "board=https://code.example.org/git/a/b.git",
		"AEMAN_FORGE":     "forgejo",
		"AEMAN_GITEA_URL": "https://code.example.org/git",
	}, nil)
	got := parseGitFlags(t, map[string]string{}, flagArgs(want))
	if got.Forge.Kind() != forge.Gitea || got.Forge.Label() != "Forgejo" || got.Forge.AuthorizeURL() != want.Forge.AuthorizeURL() {
		t.Fatalf("forge = %s %q %s, want gitea Forgejo %s", got.Forge.Kind(), got.Forge.Label(), got.Forge.AuthorizeURL(), want.Forge.AuthorizeURL())
	}
}

// A Gitea's credential comes from GITEA_TOKEN (or FORGEJO_TOKEN), then the
// keychain; there is no forge tool to fall back on, and the advice for an
// empty chain names the variable and `aeman login` — never a tool's
// `auth login` that does not exist.
func TestGiteaTokenComesFromItsVariablesAndNoTool(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/v1/user") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"login":"alice"}`)
	}))
	t.Cleanup(srv.Close)
	gt := forge.NewGitea(srv.URL, "Gitea")
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	with := func(e func(string) string) forge.CLI {
		log, _ := testLog()
		return &chain{log: log, forge: gt, sources: []forge.CLI{newEnvCLI(gt, e, guardedClient(srv)), toolFor(gt)}}
	}

	if tok, err := resolveForgeToken(ctx, gt, with(env(map[string]string{"GITEA_TOKEN": " gt-env "}))); err != nil || tok != "gt-env" {
		t.Fatalf("GITEA_TOKEN: %q %v", tok, err)
	}
	if tok, err := resolveForgeToken(ctx, gt, with(env(map[string]string{"FORGEJO_TOKEN": "fj-env"}))); err != nil || tok != "fj-env" {
		t.Fatalf("FORGEJO_TOKEN: %q %v", tok, err)
	}
	_, err := resolveForgeToken(ctx, gt, with(env(map[string]string{"GITHUB_TOKEN": "wrong-forge", "GITLAB_TOKEN": "wrong-forge"})))
	if err == nil || !strings.Contains(err.Error(), "GITEA_TOKEN") || !strings.Contains(err.Error(), "aeman login") || strings.Contains(err.Error(), "auth login") {
		t.Fatalf("no Gitea credential: %v; want GITEA_TOKEN and aeman login named, and no tool", err)
	}
	if cliNameOf(gt) != "" {
		t.Fatalf("cliNameOf(gitea) = %q; Gitea has no token tool", cliNameOf(gt))
	}
}

// The Gitea OAuth application is its own pair, and only for a Gitea board.
func TestGiteaOAuthPairMustMatchTheForge(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	gt := forge.NewGitea("https://gitea.example.org", "Gitea")
	pair := map[string]string{"AEMAN_GITEA_CLIENT_ID": "i", "AEMAN_GITEA_CLIENT_SECRET": "s"}
	if id, sec, err := oauthPair(gt, env(pair)); err != nil || id != "i" || sec != "s" {
		t.Fatalf("gitea pair: %q %q %v", id, sec, err)
	}
	if _, _, err := oauthPair(forge.NewGitHub(), env(pair)); err == nil {
		t.Fatal("a Gitea application on a GitHub board must be refused")
	}
	if _, _, err := oauthPair(gt, env(map[string]string{"AEMAN_GITLAB_CLIENT_ID": "i", "AEMAN_GITLAB_CLIENT_SECRET": "s"})); err == nil {
		t.Fatal("a GitLab application on a Gitea board must be refused")
	}
	if _, _, err := oauthPair(gt, env(map[string]string{"AEMAN_GITEA_CLIENT_ID": "i", "AEMAN_GITEA_CLIENT_SECRET": "s",
		"AEMAN_GITHUB_CLIENT_ID": "i", "AEMAN_GITHUB_CLIENT_SECRET": "s"})); err == nil {
		t.Fatal("two pairs must be refused")
	}
}
