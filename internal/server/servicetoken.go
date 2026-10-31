package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Service tokens (G82): static bearer credentials for callers that cannot
// go through a browser sign-in — an agent working the board under an
// account of its own, a bot. The operator mounts a file with one line per
// token,
//
//	<login> <sha256-hex of the token> [groups=<g1,g2>]
//
// and `Authorization: Bearer aeman_svc_…` on /api/v1 or /mcp then acts as
// that login. The server holds the hashes only; a token is never logged or
// stored. Rights are decided as for a person: by the forge, asked with the
// server's own credential (a service login has no forge token), or — in the
// OIDC mode — by the line's groups through the --oidc-access rules.

// ServiceTokenPrefix starts every service token, so one is told apart from
// an MCP session token without a lookup, and recognised in a leak.
const ServiceTokenPrefix = "aeman_svc_"

// serviceTokenBytes is how much randomness a fresh token carries.
const serviceTokenBytes = 32

// NewServiceToken is a fresh random token and the hex SHA-256 the file
// holds for it.
func NewServiceToken() (token, hash string, err error) {
	b := make([]byte, serviceTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = ServiceTokenPrefix + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// serviceAccount is who a service token acts as.
type serviceAccount struct {
	login  string
	groups []string
}

type serviceEntry struct {
	serviceAccount
	hash [sha256.Size]byte
}

// parseServiceTokens reads the file. Blank lines and # comments are
// skipped; any other line that is not a login, a 64-digit hex hash and at
// most one groups= field refuses the whole file, by line number — a typo
// must not quietly turn a token off or on. The same hash twice is refused
// too: it would make one token two logins.
func parseServiceTokens(data []byte) ([]serviceEntry, error) {
	var out []serviceEntry
	seen := map[[sha256.Size]byte]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want <login> <sha256-hex> [groups=<g1,g2>]", i+1)
		}
		raw, err := hex.DecodeString(fields[1])
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("line %d: the second field must be the token's SHA-256 as 64 hex digits (the token itself never goes in the file)", i+1)
		}
		e := serviceEntry{serviceAccount: serviceAccount{login: fields[0]}}
		copy(e.hash[:], raw)
		if seen[e.hash] {
			return nil, fmt.Errorf("line %d: the same token hash is listed twice", i+1)
		}
		seen[e.hash] = true
		for _, f := range fields[2:] {
			v, ok := strings.CutPrefix(f, "groups=")
			if !ok {
				return nil, fmt.Errorf("line %d: unknown field %q (only groups=<g1,g2>)", i+1, f)
			}
			if e.groups != nil {
				return nil, fmt.Errorf("line %d: groups= is given twice", i+1)
			}
			for _, g := range strings.Split(v, ",") {
				if g = strings.TrimSpace(g); g != "" {
					e.groups = append(e.groups, g)
				}
			}
			if len(e.groups) == 0 {
				return nil, fmt.Errorf("line %d: groups= names no group", i+1)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// serviceTokens is the file, re-read when it changes (its size or
// modification time moves — a Secret mount swapped, an edit saved). A file
// that is broken or gone after the start admits nobody until it is fixed:
// the token an operator was revoking must not keep working because of a
// typo in the same edit.
type serviceTokens struct {
	path string
	// groups reports whether lines may carry groups (the OIDC mode).
	groups bool
	log    *slog.Logger

	mu      sync.Mutex
	size    int64
	mod     time.Time
	entries []serviceEntry
}

// openServiceTokens reads the file once; at start any problem is an error.
func openServiceTokens(path string, groups bool, log *slog.Logger) (*serviceTokens, error) {
	t := &serviceTokens{path: path, groups: groups, log: log}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("service tokens: %w", err)
	}
	entries, err := t.read()
	if err != nil {
		return nil, fmt.Errorf("service tokens %s: %w", path, err)
	}
	t.size, t.mod, t.entries = fi.Size(), fi.ModTime(), entries
	return t, nil
}

func (t *serviceTokens) read() ([]serviceEntry, error) {
	data, err := os.ReadFile(t.path)
	if err != nil {
		return nil, err
	}
	entries, err := parseServiceTokens(data)
	if err != nil {
		return nil, err
	}
	if !t.groups {
		for _, e := range entries {
			if e.groups != nil {
				return nil, fmt.Errorf("%s has groups=, which only the OIDC sign-in reads: in the forge mode the forge decides a login's rights", e.login)
			}
		}
	}
	return entries, nil
}

// current is the entries as the file stands now.
func (t *serviceTokens) current() []serviceEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	fi, err := os.Stat(t.path)
	if err != nil {
		if t.size >= 0 { // say it once, not on every request
			t.warn("service tokens file is gone; no service token is accepted until it is back", err)
		}
		t.entries, t.size, t.mod = nil, -1, time.Time{}
		return nil
	}
	if fi.Size() == t.size && fi.ModTime().Equal(t.mod) {
		return t.entries
	}
	entries, err := t.read()
	if err != nil {
		t.warn("service tokens file does not parse; no service token is accepted until it is fixed", err)
		entries = nil
	} else if t.log != nil {
		t.log.Info("service tokens re-read", "path", t.path, "tokens", len(entries))
	}
	t.size, t.mod, t.entries = fi.Size(), fi.ModTime(), entries
	return entries
}

func (t *serviceTokens) warn(msg string, err error) {
	if t.log != nil {
		t.log.Warn(msg, "path", t.path, "err", err)
	}
}

// lookup is who a token acts as. Every entry is compared, in constant time,
// whatever matched before: how long the answer takes says nothing about
// which hash came close.
func (t *serviceTokens) lookup(token string) (serviceAccount, bool) {
	if t == nil || !strings.HasPrefix(token, ServiceTokenPrefix) || len(token) == len(ServiceTokenPrefix) {
		return serviceAccount{}, false
	}
	sum := sha256.Sum256([]byte(token))
	var found serviceAccount
	ok := false
	for _, e := range t.current() {
		if subtle.ConstantTimeCompare(sum[:], e.hash[:]) == 1 {
			found, ok = e.serviceAccount, true
		}
	}
	return found, ok
}

// isServiceToken reports whether a bearer credential claims to be one.
func isServiceToken(token string) bool { return strings.HasPrefix(token, ServiceTokenPrefix) }

// bearer is the request's bearer credential, "" without one.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

type serviceCtxKey struct{}

func withService(ctx context.Context, a serviceAccount) context.Context {
	return context.WithValue(ctx, serviceCtxKey{}, a)
}

// serviceFrom is the service account a request acts as, if it does.
func serviceFrom(ctx context.Context) (serviceAccount, bool) {
	a, ok := ctx.Value(serviceCtxKey{}).(serviceAccount)
	return a, ok
}

// serviceMiddleware resolves a service token on an /api/v1 request and
// stamps the account on the context, where the identity and access
// middlewares read it. A bearer credential that claims to be a service
// token and is not one is refused here: falling through to the session
// cookie would let a stale agent run as whoever's browser it sits in.
func (s *Server) serviceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if s.auth == nil || s.auth.services == nil || !strings.HasPrefix(r.URL.Path, "/api/v1") || !isServiceToken(tok) {
			next.ServeHTTP(w, r)
			return
		}
		acct, ok := s.auth.services.lookup(tok)
		if !ok {
			writeProblem(w, problem(http.StatusUnauthorized, "notAuthenticated", "not authenticated: unknown service token"))
			return
		}
		next.ServeHTTP(w, r.WithContext(withService(r.Context(), acct)))
	})
}

// serviceAccess is a domainAccess that can decide a service account's
// rights — it has no token of its own to be asked with.
type serviceAccess interface {
	serviceRights(ctx context.Context, a serviceAccount) (*domainRights, error)
}

// errNoServiceAccess is an access layer that cannot answer for a service
// account (the single-user server's).
var errNoServiceAccess = errors.New("service tokens are not accepted by this server")

// serviceRights is what a service account may read and write.
func (s *Server) serviceRights(ctx context.Context, a serviceAccount) (*domainRights, error) {
	sa, ok := s.access.(serviceAccess)
	if !ok {
		return nil, errNoServiceAccess
	}
	return sa.serviceRights(ctx, a)
}

// serviceRights in the OIDC mode: the line's groups through the rules, as a
// person's groups go — the provider is not asked, it does not know the
// login.
func (o *oidcAccess) serviceRights(_ context.Context, a serviceAccount) (*domainRights, error) {
	return o.decided(rightsOf(o.rules, o.domains, a.groups))
}

// serviceRights in the forge mode: the server's credential asks the forge
// what the login may do with each domain, cached per login for the TTL. A
// forge that cannot be reached leaves the last answer standing.
func (f *forgeAccess) serviceRights(ctx context.Context, a serviceAccount) (*domainRights, error) {
	f.mu.Lock()
	if f.services == nil {
		f.services = map[string]cachedRights{}
	}
	c, cached := f.services[a.login]
	f.mu.Unlock()
	if cached && f.now().Sub(c.at) < f.ttl {
		return c.rights, nil
	}
	r := &domainRights{primary: f.domains[0].Name, read: map[string]bool{}, write: map[string]bool{}}
	for _, d := range f.domains {
		tok := f.tokenFor(ctx, d.Name)
		read, write, err := f.forge.Permission(ctx, f.client, tok, d.URL, a.login)
		if err != nil {
			if cached {
				f.log("service rights could not be asked; the last answer stands", a.login, err)
				return c.rights, nil
			}
			return nil, fmt.Errorf("access to %s: %w", d.Name, err)
		}
		r.read[d.Name] = read
		r.write[d.Name] = write
	}
	f.mu.Lock()
	f.services[a.login] = cachedRights{rights: r, at: f.now()}
	f.mu.Unlock()
	return r, nil
}
