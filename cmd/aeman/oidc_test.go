package main

import (
	"strings"
	"testing"

	"github.com/aenix-io/aeman/internal/forge"
	"github.com/aenix-io/aeman/internal/server"
)

func oidcEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func oidcGitConfig() *server.GitConfig {
	return &server.GitConfig{Forge: forge.NewGitHub(), Token: "server-token",
		Repos: []server.RepoSpec{{Name: "shared", URL: "https://github.com/acme/shared", Token: "server-token"}}}
}

func goodOIDCEnv() map[string]string {
	return map[string]string{
		"AEMAN_OIDC_ISSUER":        "https://sso.example.test/realms/eng",
		"AEMAN_OIDC_CLIENT_ID":     "aeman",
		"AEMAN_OIDC_CLIENT_SECRET": "s3cret",
		"AEMAN_BASE_URL":           "https://aeman.example.test",
		"AEMAN_OIDC_ACCESS":        "shared=devs:write, *=auditors:read",
	}
}

// G81 — the configuration from the environment: the issuer turns the mode
// on, the rules come comma-separated, the claims and the name pass through.
func TestOIDCAuthFromTheEnvironment(t *testing.T) {
	env := goodOIDCEnv()
	env["AEMAN_OIDC_NAME"] = "Corp SSO"
	env["AEMAN_OIDC_LOGIN_CLAIM"] = "email"
	cfg, err := oidcAuth(&oidcFlags{}, oidcGitConfig(), oidcEnv(env))
	if err != nil || cfg == nil || cfg.OIDC == nil {
		t.Fatalf("oidcAuth = %+v, %v", cfg, err)
	}
	if cfg.ClientID != "aeman" || cfg.OIDC.Issuer != env["AEMAN_OIDC_ISSUER"] || cfg.OIDC.Name != "Corp SSO" || cfg.OIDC.LoginClaim != "email" {
		t.Fatalf("config = %+v %+v", cfg, cfg.OIDC)
	}
	want := []server.OIDCRule{{Domain: "shared", Group: "devs", Write: true}, {Domain: "*", Group: "auditors"}}
	if len(cfg.OIDC.Access) != 2 || cfg.OIDC.Access[0] != want[0] || cfg.OIDC.Access[1] != want[1] {
		t.Fatalf("rules = %+v, want %+v", cfg.OIDC.Access, want)
	}
	// The flags win over the environment.
	cfg, err = oidcAuth(&oidcFlags{issuer: "https://other.example.test", access: []string{"shared=ops:read"}}, oidcGitConfig(), oidcEnv(env))
	if err != nil || cfg.OIDC.Issuer != "https://other.example.test" || len(cfg.OIDC.Access) != 1 || cfg.OIDC.Access[0].Group != "ops" {
		t.Fatalf("flags: %+v, %v", cfg, err)
	}
	// No issuer is not OIDC mode, and not an error.
	if cfg, err := oidcAuth(&oidcFlags{}, oidcGitConfig(), oidcEnv(nil)); cfg != nil || err != nil {
		t.Fatalf("no issuer: %+v, %v", cfg, err)
	}
}

// G81 — what is refused at start: OIDC beside a forge's OAuth pair (one
// sign-in per server), no base URL, no client, no server credential, no
// rule, a bad rule, a plain-http issuer, rules without an issuer.
func TestOIDCAuthRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		edit  func(env map[string]string, cfg *server.GitConfig)
		flags *oidcFlags
		want  string
	}{
		"with a GitHub OAuth pair": {edit: func(e map[string]string, _ *server.GitConfig) {
			e["AEMAN_GITHUB_CLIENT_ID"], e["AEMAN_GITHUB_CLIENT_SECRET"] = "i", "s"
		}, want: "one way"},
		"with a GitLab OAuth pair": {edit: func(e map[string]string, _ *server.GitConfig) {
			e["AEMAN_GITLAB_CLIENT_ID"], e["AEMAN_GITLAB_CLIENT_SECRET"] = "i", "s"
		}, want: "one way"},
		"no base URL":     {edit: func(e map[string]string, _ *server.GitConfig) { delete(e, "AEMAN_BASE_URL") }, want: "AEMAN_BASE_URL"},
		"no client":       {edit: func(e map[string]string, _ *server.GitConfig) { delete(e, "AEMAN_OIDC_CLIENT_SECRET") }, want: "AEMAN_OIDC_CLIENT_SECRET"},
		"no server token": {edit: func(_ map[string]string, c *server.GitConfig) { c.Token, c.Repos[0].Token = "", "" }, want: "no credential"},
		"no rule":         {edit: func(e map[string]string, _ *server.GitConfig) { delete(e, "AEMAN_OIDC_ACCESS") }, want: "at least one"},
		"a bad rule":      {edit: func(e map[string]string, _ *server.GitConfig) { e["AEMAN_OIDC_ACCESS"] = "shared=devs:admin" }, want: "read or write"},
		"a plain-http issuer": {edit: func(e map[string]string, _ *server.GitConfig) {
			e["AEMAN_OIDC_ISSUER"] = "http://sso.example.test"
		}, want: "https"},
		"rules without an issuer": {edit: func(e map[string]string, _ *server.GitConfig) { delete(e, "AEMAN_OIDC_ISSUER") }, want: "without --oidc-issuer"},
	} {
		t.Run(name, func(t *testing.T) {
			env, cfg := goodOIDCEnv(), oidcGitConfig()
			c.edit(env, cfg)
			flags := c.flags
			if flags == nil {
				flags = &oidcFlags{}
			}
			got, err := oidcAuth(flags, cfg, oidcEnv(env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("oidcAuth = %+v, %v; want an error naming %q", got, err, c.want)
			}
		})
	}
}
