package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/aenix-io/aeman/internal/server"
)

// oidcFlags are serve's flags for signing people in through an OpenID
// Connect provider instead of the forge. The client secret, like the
// forge's, is read from the environment only, so it stays out of `ps`.
type oidcFlags struct {
	issuer string
	access []string
}

func addOIDCFlags(fs *flag.FlagSet) *oidcFlags {
	o := &oidcFlags{}
	fs.StringVar(&o.issuer, "oidc-issuer", "", "sign people in through this OpenID Connect issuer instead of the forge (env AEMAN_OIDC_ISSUER)")
	fs.Func("oidc-access", "access rule <domain>=<group>:<read|write>, '*' for every domain (repeatable; env AEMAN_OIDC_ACCESS, comma-separated)", func(v string) error {
		o.access = append(o.access, v)
		return nil
	})
	return o
}

// oidcAuth is the OAuth-mode configuration that signs in through an OIDC
// provider, or nil when no issuer is configured. It is refused beside a
// forge's OAuth pair — one sign-in per server — and it needs the public
// base URL and a server credential for every repository: the visitor's
// token is the provider's and never reaches the forge, so the server alone
// pushes. With no access rule nobody could sign in, which is refused too.
func oidcAuth(o *oidcFlags, cfg *server.GitConfig, env func(string) string) (*server.OAuthConfig, error) {
	issuer := o.issuer
	if issuer == "" {
		issuer = env("AEMAN_OIDC_ISSUER")
	}
	if issuer == "" {
		if len(o.access) > 0 || env("AEMAN_OIDC_ACCESS") != "" {
			return nil, errors.New("--oidc-access is set without --oidc-issuer (AEMAN_OIDC_ISSUER)")
		}
		return nil, nil
	}
	if err := server.CheckOIDCIssuer(issuer); err != nil {
		return nil, err
	}
	if id, _, err := oauthPair(cfg.Forge, env); err != nil || id != "" {
		return nil, fmt.Errorf("an OIDC issuer and a forge OAuth application are both configured; a server signs people in one way — unset the AEMAN_*_CLIENT_ID/SECRET pair of the forge, or AEMAN_OIDC_ISSUER")
	}
	id, secret := env("AEMAN_OIDC_CLIENT_ID"), env("AEMAN_OIDC_CLIENT_SECRET")
	if id == "" || secret == "" {
		return nil, errors.New("OIDC sign-in needs AEMAN_OIDC_CLIENT_ID and AEMAN_OIDC_CLIENT_SECRET")
	}
	baseURL := env("AEMAN_BASE_URL")
	if baseURL == "" {
		return nil, errors.New("AEMAN_BASE_URL is required when OIDC sign-in is configured")
	}
	if missing := missingTokens(cfg); len(missing) > 0 && cfg.App == nil {
		return nil, fmt.Errorf("no credential for %s: with OIDC sign-in the server pushes every repository of the board with its own token — set AEMAN_GIT_TOKEN, a token per repository, or a GitHub App (AEMAN_GITHUB_APP_ID + key)",
			strings.Join(missing, ", "))
	}
	raw := append([]string(nil), o.access...)
	if len(raw) == 0 {
		for _, r := range strings.Split(env("AEMAN_OIDC_ACCESS"), ",") {
			if strings.TrimSpace(r) != "" {
				raw = append(raw, r)
			}
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("OIDC sign-in needs at least one --oidc-access rule (AEMAN_OIDC_ACCESS): access is denied by default, so without one nobody could sign in")
	}
	rules := make([]server.OIDCRule, 0, len(raw))
	for _, r := range raw {
		rule, err := server.ParseOIDCAccess(r)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return &server.OAuthConfig{
		ClientID:     id,
		ClientSecret: secret,
		BaseURL:      baseURL,
		Scopes:       env("AEMAN_OIDC_SCOPES"),
		SessionFile:  env("AEMAN_SESSION_FILE"),
		SessionKey:   env("AEMAN_SESSION_KEY"),
		OIDC: &server.OIDCConfig{
			Issuer:      issuer,
			LoginClaim:  env("AEMAN_OIDC_LOGIN_CLAIM"),
			GroupsClaim: env("AEMAN_OIDC_GROUPS_CLAIM"),
			Name:        env("AEMAN_OIDC_NAME"),
			Access:      rules,
		},
	}, nil
}
