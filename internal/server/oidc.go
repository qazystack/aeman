package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/aenix-io/aeman/internal/forge"
)

// Signing in through an OpenID Connect provider (Authentik, Keycloak,
// Zitadel, Dex, …) instead of the forge. The provider says who the visitor
// is and which groups they are in; the operator's access rules turn groups
// into read and write per domain. The forge stays the remote the board
// lives on, reached only with the server's credential — the visitor's
// token is the provider's and never touches git.
//
// The protocol itself — discovery, the PKCE code exchange, the ID token's
// signature and claims — is github.com/coreos/go-oidc and
// golang.org/x/oauth2, not code of ours: a hand-rolled JWT check is where
// sign-in bugs live.

// OIDC defaults, mirrored in docs/api.md.
const (
	DefaultOIDCScopes      = "openid profile email groups"
	DefaultOIDCLoginClaim  = "preferred_username"
	DefaultOIDCGroupsClaim = "groups"
	DefaultOIDCName        = "SSO"
)

// OIDCConfig turns the OAuth mode's sign-in over to an OpenID Connect
// provider. The client id, secret, scopes, base URL and session file are
// OAuthConfig's; this is what is particular to OIDC.
type OIDCConfig struct {
	// Issuer is the provider's issuer URL; its discovery document must name
	// exactly this issuer. https, or plain http on a loopback host.
	Issuer string
	// LoginClaim is the claim the visitor's login is read from — the name
	// cards are assigned to and commits are attributed to.
	LoginClaim string
	// GroupsClaim is the claim the visitor's groups are read from.
	GroupsClaim string
	// Name is the provider's display name on the sign-in button.
	Name string
	// Access are the rules that turn groups into rights. A domain no rule
	// grants is invisible: deny by default.
	Access []OIDCRule
}

// OIDCRule grants one group read, or read and write, on one domain — or on
// every configured domain when Domain is "*".
type OIDCRule struct {
	Domain string
	Group  string
	Write  bool
}

// ParseOIDCAccess reads one access rule in the flag's form,
// <domain>=<group>:<read|write>. The group may itself contain ':' (a
// provider path such as "org:team"); the level is what follows the last one.
func ParseOIDCAccess(s string) (OIDCRule, error) {
	s = strings.TrimSpace(s)
	domain, rest, ok := strings.Cut(s, "=")
	if !ok {
		return OIDCRule{}, fmt.Errorf("oidc access %q: want <domain>=<group>:<read|write>", s)
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return OIDCRule{}, fmt.Errorf("oidc access %q: want <domain>=<group>:<read|write>", s)
	}
	group, level := strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:])
	domain = strings.TrimSpace(domain)
	if domain == "" || group == "" {
		return OIDCRule{}, fmt.Errorf("oidc access %q: the domain and the group must not be empty", s)
	}
	switch level {
	case "read":
		return OIDCRule{Domain: domain, Group: group}, nil
	case "write":
		return OIDCRule{Domain: domain, Group: group, Write: true}, nil
	}
	return OIDCRule{}, fmt.Errorf("oidc access %q: the level is read or write, not %q", s, level)
}

// CheckOIDCIssuer refuses an issuer the sign-in must not trust: anything
// but https, except plain http on a loopback host (a provider on the same
// machine, and tests).
func CheckOIDCIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("oidc issuer %q is not a URL", issuer)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("oidc issuer %q must be https (plain http only on a loopback host)", issuer)
}

// rightsOf is what a set of groups may do with the board's domains, by the
// rules: write implies read, several rules for one domain add up, "*" is
// every domain. The primary is the board's first domain, as for the forge.
func rightsOf(rules []OIDCRule, domains []string, groups []string) *domainRights {
	r := &domainRights{read: map[string]bool{}, write: map[string]bool{}}
	if len(domains) > 0 {
		r.primary = domains[0]
	}
	in := make(map[string]bool, len(groups))
	for _, g := range groups {
		in[g] = true
	}
	for _, rule := range rules {
		if !in[rule.Group] {
			continue
		}
		for _, d := range domains {
			if rule.Domain != "*" && rule.Domain != d {
				continue
			}
			r.read[d] = true
			if rule.Write {
				r.write[d] = true
			}
		}
	}
	return r
}

// readsAny reports whether the rights open at least one domain.
func (r *domainRights) readsAny() bool {
	for _, ok := range r.read {
		if ok {
			return true
		}
	}
	return false
}

// errNoReadableDomain is a visitor the access rules open no domain to.
var errNoReadableDomain = errors.New("none of this board's repositories is open to your groups")

// oidcPerson is what the provider said about someone who signed in: the
// directory the board's people and the assignee picker are answered from.
// It never holds a token.
type oidcPerson struct {
	Login      string    `json:"login"`
	Name       string    `json:"name,omitempty"`
	Email      string    `json:"email,omitempty"`
	AvatarURL  string    `json:"avatarUrl,omitempty"`
	Groups     []string  `json:"groups,omitempty"`
	LastSignIn time.Time `json:"lastSignIn"`
}

// oidcIdentity is the provider side of the sign-in: discovery (lazily, and
// again after a failure, so a provider that is down at start does not keep
// the server down), the authorize URL, the code exchange and the ID token
// check, the userinfo call and the refresh.
type oidcIdentity struct {
	cfg          OIDCConfig
	clientID     string
	clientSecret string
	scopes       []string
	redirectURI  string
	client       *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
}

func newOIDCIdentity(cfg OIDCConfig, clientID, secret, scopes, redirectURI string, client *http.Client) *oidcIdentity {
	if cfg.LoginClaim == "" {
		cfg.LoginClaim = DefaultOIDCLoginClaim
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = DefaultOIDCGroupsClaim
	}
	if cfg.Name == "" {
		cfg.Name = DefaultOIDCName
	}
	if scopes == "" {
		scopes = DefaultOIDCScopes
	}
	return &oidcIdentity{cfg: cfg, clientID: clientID, clientSecret: secret,
		scopes: strings.Fields(scopes), redirectURI: redirectURI, client: client}
}

// ctx carries the identity's HTTP client to the libraries.
func (o *oidcIdentity) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, o.client)
}

// discover is the provider, read from its discovery document once it has
// been read successfully. go-oidc refuses a document whose issuer is not
// the configured one.
func (o *oidcIdentity) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	if err := CheckOIDCIssuer(o.cfg.Issuer); err != nil {
		return nil, err
	}
	// The key set is fetched later, on the context given here: it must not
	// be the request's, which ends with the request.
	p, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), o.client), o.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	o.provider = p
	return p, nil
}

func (o *oidcIdentity) oauth2(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  o.redirectURI,
		Scopes:       o.scopes,
	}
}

// authCodeURL is where the visitor is sent to sign in: the code flow with
// PKCE (S256), the state and the nonce.
func (o *oidcIdentity) authCodeURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	return o.oauth2(p).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// signIn exchanges the code (with the PKCE verifier), verifies the ID token
// — signature by the provider's keys, iss, aud, exp, and the nonce this
// flow sent — and reads who the visitor is. What the ID token does not
// carry is asked of the userinfo endpoint.
func (o *oidcIdentity) signIn(ctx context.Context, code, verifier, nonce string) (ghGrant, oidcPerson, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return ghGrant{}, oidcPerson{}, err
	}
	tok, err := o.oauth2(p).Exchange(o.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return ghGrant{}, oidcPerson{}, fmt.Errorf("oidc code exchange: %w", err)
	}
	claims, err := o.verify(ctx, p, tok, nonce)
	if err != nil {
		return ghGrant{}, oidcPerson{}, err
	}
	grant := grantOf(tok)
	person := o.personOf(claims)
	_, groupsInToken := claims[o.cfg.GroupsClaim]
	if person.Login == "" || !groupsInToken {
		// The ID token is a summary some providers keep short; the userinfo
		// endpoint has the rest. Only what the token lacks is taken from it.
		info, err := o.userinfo(ctx, grant.token)
		if err != nil && !errors.Is(err, errNoUserinfo) {
			return ghGrant{}, oidcPerson{}, err
		}
		if info != nil {
			more := o.personOf(info)
			if person.Login == "" {
				person.Login = more.Login
			}
			if person.Name == "" {
				person.Name = more.Name
			}
			if person.Email == "" {
				person.Email = more.Email
			}
			if person.AvatarURL == "" {
				person.AvatarURL = more.AvatarURL
			}
			if !groupsInToken {
				person.Groups = more.Groups
			}
		}
	}
	if person.Login == "" {
		return ghGrant{}, oidcPerson{}, fmt.Errorf("oidc: neither the ID token nor userinfo carries the login claim %q", o.cfg.LoginClaim)
	}
	return grant, person, nil
}

// verify checks the ID token in a token response and returns its claims.
// An empty nonce skips the nonce check: a refresh's ID token carries none.
func (o *oidcIdentity) verify(ctx context.Context, p *oidc.Provider, tok *oauth2.Token, nonce string) (map[string]any, error) {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("oidc: the token response carries no id_token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: o.clientID}).Verify(o.ctx(ctx), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIDTokenRefused, err)
	}
	if nonce != "" && idt.Nonce != nonce {
		return nil, fmt.Errorf("%w: the nonce is not the one this sign-in sent", errIDTokenRefused)
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: id token claims: %w", err)
	}
	return claims, nil
}

// refresh renews the access token with the refresh token. A refreshed ID
// token, when the provider sends one, is checked and its person returned:
// the groups in it are the provider's latest word.
func (o *oidcIdentity) refresh(ctx context.Context, refresh string) (ghGrant, *oidcPerson, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return ghGrant{}, nil, err
	}
	tok, err := o.oauth2(p).TokenSource(o.ctx(ctx), &oauth2.Token{RefreshToken: refresh, Expiry: time.Unix(1, 0)}).Token()
	if err != nil {
		return ghGrant{}, nil, fmt.Errorf("oidc refresh: %w", err)
	}
	grant := grantOf(tok)
	if grant.refresh == refresh {
		grant.refresh = "" // the provider kept it; renewSession keeps the old one
	}
	if _, ok := tok.Extra("id_token").(string); !ok {
		return grant, nil, nil
	}
	claims, err := o.verify(ctx, p, tok, "")
	if err != nil {
		return ghGrant{}, nil, err
	}
	if _, ok := claims[o.cfg.GroupsClaim]; !ok {
		return grant, nil, nil
	}
	person := o.personOf(claims)
	return grant, &person, nil
}

// errIDTokenRefused is an ID token that does not pass: a bad signature, an
// issuer or audience that is not ours, an expired token, a stray nonce.
var errIDTokenRefused = errors.New("oidc: id token refused")

// errNoUserinfo is a provider that has no userinfo endpoint.
var errNoUserinfo = errors.New("oidc: the provider has no userinfo endpoint")

// userinfo asks the provider about the bearer of an access token. A 401 is
// errBadVisitorToken — the session is over — like the forge refusing a
// visitor's token.
func (o *oidcIdentity) userinfo(ctx context.Context, token string) (map[string]any, error) {
	p, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := p.UserInfoEndpoint()
	if endpoint == "" {
		return nil, errNoUserinfo
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) //nolint:gosec // G704: the endpoint is the configured issuer's own discovery answer
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req) //nolint:gosec // G704: the endpoint is the configured issuer's own discovery answer
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("oidc userinfo: %w", forge.ErrBadToken)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("oidc userinfo: HTTP %d", resp.StatusCode)
	}
	out := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("oidc userinfo: %w", err)
	}
	return out, nil
}

// personOf reads a person out of a set of claims (an ID token's or
// userinfo's), by the configured login and groups claims.
func (o *oidcIdentity) personOf(claims map[string]any) oidcPerson {
	str := func(k string) string {
		s, _ := claims[k].(string)
		return s
	}
	return oidcPerson{
		Login:     str(o.cfg.LoginClaim),
		Name:      str("name"),
		Email:     str("email"),
		AvatarURL: str("picture"),
		Groups:    stringsClaim(claims[o.cfg.GroupsClaim]),
	}
}

// groupsFrom is the groups claim of a userinfo answer, and whether the
// answer carries the claim at all.
func (o *oidcIdentity) groupsFrom(claims map[string]any) ([]string, bool) {
	v, ok := claims[o.cfg.GroupsClaim]
	if !ok {
		return nil, false
	}
	return stringsClaim(v), true
}

// stringsClaim reads a claim that is a list of strings — or, as some
// providers send a single group, one string.
func stringsClaim(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// grantOf is an oauth2 token in the session's terms.
func grantOf(tok *oauth2.Token) ghGrant {
	return ghGrant{token: tok.AccessToken, refresh: tok.RefreshToken, expiry: tok.Expiry}
}
