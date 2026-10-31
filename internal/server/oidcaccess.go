package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/aenix-io/aeman/internal/forge"
)

// oidcDirectory is the people who have signed in through the provider —
// login, name, avatar, groups, last sign-in — kept in the session file
// next to the sessions. It answers who may be assigned (readers) and what
// the board shows for a login. Someone who never signed in is not in it.
type oidcDirectory struct {
	mu     sync.Mutex
	people map[string]oidcPerson
	// save persists the directory (the auth manager's session file); nil
	// keeps it in memory.
	save func()
}

func newOIDCDirectory() *oidcDirectory {
	return &oidcDirectory{people: map[string]oidcPerson{}}
}

// remember records a sign-in: everything the provider said, now.
func (d *oidcDirectory) remember(p oidcPerson, at time.Time) {
	p.LastSignIn = at
	d.mu.Lock()
	d.people[p.Login] = p
	save := d.save
	d.mu.Unlock()
	if save != nil {
		save()
	}
}

// setGroups updates a known person's groups — the provider's latest word —
// and persists only when they changed.
func (d *oidcDirectory) setGroups(login string, groups []string) {
	d.mu.Lock()
	p, ok := d.people[login]
	if !ok || slices.Equal(p.Groups, groups) {
		d.mu.Unlock()
		return
	}
	p.Groups = append([]string(nil), groups...)
	d.people[login] = p
	save := d.save
	d.mu.Unlock()
	if save != nil {
		save()
	}
}

// get is one person, if they have signed in.
func (d *oidcDirectory) get(login string) (oidcPerson, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.people[login]
	return p, ok
}

// snapshot is a copy for the session file.
func (d *oidcDirectory) snapshot() map[string]oidcPerson {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]oidcPerson, len(d.people))
	for k, v := range d.people {
		out[k] = v
	}
	return out
}

// restore loads the directory from the session file, without saving.
func (d *oidcDirectory) restore(people map[string]oidcPerson) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range people {
		if k != "" {
			v.Login = k
			d.people[k] = v
		}
	}
}

// lookup is the directory as the board's people source: a login nobody
// signed in as is forge.ErrNotFound, and the boards show initials.
func (d *oidcDirectory) lookup(_ context.Context, login string) (forge.Person, error) {
	p, ok := d.get(login)
	if !ok {
		return forge.Person{}, forge.ErrNotFound
	}
	return forge.Person{Login: login, Name: p.Name, AvatarURL: p.AvatarURL}, nil
}

// oidcAccess decides rights from the provider's groups and the operator's
// rules (G81). The answer is cached per visitor for accessTTL; after that
// the groups are asked again — userinfo with the session's access token —
// so someone taken out of a group loses the domain within accessTTL, and a
// token the provider refuses (401) ends the session the way a token the
// forge refuses does. A provider that is merely unreachable leaves the last
// answer standing.
type oidcAccess struct {
	id      *oidcIdentity
	dir     *oidcDirectory
	rules   []OIDCRule
	domains []string
	ttl     time.Duration
	now     func() time.Time
	logger  *slog.Logger
	// services is the tokens file, whose lines are members too (G83); nil
	// without one.
	services *serviceTokens

	mu    sync.Mutex
	cache map[string]cachedRights // by login
}

func newOIDCAccess(id *oidcIdentity, dir *oidcDirectory, rules []OIDCRule, domains []string) *oidcAccess {
	return &oidcAccess{id: id, dir: dir, rules: rules, domains: domains,
		ttl: accessTTL, now: time.Now, cache: map[string]cachedRights{}}
}

// checkRules refuses a rule naming a domain the board does not have: a typo
// there would quietly deny everyone.
func checkOIDCRules(rules []OIDCRule, domains []string) error {
	for _, r := range rules {
		if r.Domain != "*" && !slices.Contains(domains, r.Domain) {
			return fmt.Errorf("oidc access rule for %q: the board has no such domain (domains: %v)", r.Domain, domains)
		}
	}
	return nil
}

// admit decides a fresh sign-in from the groups the provider just gave: a
// visitor no domain is open to is refused there, and anyone else starts
// with a fresh answer, so the first board load asks nobody.
func (o *oidcAccess) admit(p oidcPerson) error {
	r := rightsOf(o.rules, o.domains, p.Groups)
	if !r.readsAny() {
		return errNoReadableDomain
	}
	o.mu.Lock()
	o.cache[p.Login] = cachedRights{rights: r, at: o.now()}
	o.mu.Unlock()
	return nil
}

func (o *oidcAccess) rights(ctx context.Context, token, login string) (*domainRights, error) {
	o.mu.Lock()
	c, cached := o.cache[login]
	o.mu.Unlock()
	if cached && o.now().Sub(c.at) < o.ttl {
		return o.decided(c.rights)
	}
	groups, err := o.groups(ctx, token, login)
	if err != nil {
		if errors.Is(err, errBadVisitorToken) {
			o.mu.Lock()
			delete(o.cache, login)
			o.mu.Unlock()
			return nil, err
		}
		if cached {
			if o.logger != nil {
				o.logger.Warn("oidc groups could not be asked; the last answer stands", "login", login, "err", err)
			}
			return o.decided(c.rights)
		}
		return nil, err
	}
	r := rightsOf(o.rules, o.domains, groups)
	o.mu.Lock()
	o.cache[login] = cachedRights{rights: r, at: o.now()}
	o.mu.Unlock()
	o.dir.setGroups(login, groups)
	return o.decided(r)
}

// decided is the answer, or the refusal of a visitor no domain is open to.
func (o *oidcAccess) decided(r *domainRights) (*domainRights, error) {
	if !r.readsAny() {
		return nil, errNoReadableDomain
	}
	return r, nil
}

// groups asks the provider for the visitor's groups now. A userinfo answer
// without the groups claim (a provider that puts groups in the ID token
// only) falls back to the groups of the last ID token, from the directory.
func (o *oidcAccess) groups(ctx context.Context, token, login string) ([]string, error) {
	info, err := o.id.userinfo(ctx, token)
	switch {
	case errors.Is(err, errNoUserinfo):
	case err != nil:
		return nil, err
	default:
		if g, ok := o.id.groupsFrom(info); ok {
			return g, nil
		}
	}
	p, ok := o.dir.get(login)
	if !ok {
		return nil, fmt.Errorf("oidc: no groups known for %q", login)
	}
	return p.Groups, nil
}

// readers is the subset of logins that may read the domain: people in the
// directory whose last known groups open it, and service-token logins whose
// line's groups do (G83). A login that is both is the person: their groups
// decide. Someone who never signed in and has no token line is not offered.
func (o *oidcAccess) readers(_ context.Context, domain string, logins []string) ([]string, error) {
	if !slices.Contains(o.domains, domain) {
		return nil, fmt.Errorf("unknown domain %q", domain)
	}
	tokens := o.services.accounts()
	out := make([]string, 0, len(logins))
	for _, login := range logins {
		var groups []string
		if p, ok := o.dir.get(login); ok {
			groups = p.Groups
		} else if a, ok := tokens[login]; ok {
			groups = a.groups
		} else {
			continue
		}
		if rightsOf(o.rules, o.domains, groups).canRead(domain) {
			out = append(out, login)
		}
	}
	return out, nil
}

// lookupWithTokens is the people source of the OIDC mode: the directory
// first — a person who signed in is shown as the provider describes them —
// then a service-token line, shown with its name=, else its login (G83).
func lookupWithTokens(dir *oidcDirectory, services *serviceTokens) func(context.Context, string) (forge.Person, error) {
	return func(ctx context.Context, login string) (forge.Person, error) {
		p, err := dir.lookup(ctx, login)
		if err == nil || services == nil {
			return p, err
		}
		a, ok := services.accounts()[login]
		if !ok {
			return forge.Person{}, forge.ErrNotFound
		}
		name := a.name
		if name == "" {
			name = login
		}
		return forge.Person{Login: login, Name: name}, nil
	}
}
