# Fork roadmap

Order matters: each step is one branch and one PR. The architect marks a step done here when merging it.

Upstream is about to rework the domain (new entities such as Initiative and Epic). So the fork does not touch the domain,
the board service or the storage: `pkg/board`, `pkg/boardservice`, `pkg/gitstore`, `pkg/apiserver`, `pkg/mcpserver`, the
board views in `web/`. Work stays at the edges: forges, sign-in, packaging.

## 1. Gitea / Forgejo forge — done
A third adapter in `internal/forge` beside GitHub and GitLab (`docs/design/git-backend.md`, "Forge-agnostic by construction",
already names Gitea as the next adapter). One adapter serves both Gitea and Forgejo (Forgejo keeps the Gitea API v1).
- `internal/forge/gitea.go`: OAuth2 authorize/token URLs (`/login/oauth/authorize`, `/login/oauth/access_token`), read scopes
  for user and repository (the visitor's token never pushes; the server token does, as with GitLab), `User` (`GET /api/v1/user`), `Access` (`GET /api/v1/repos/{owner}/{repo}`, `permissions`),
  `Readers` / `Lookup` (collaborators and users), avatars, `RepoRef`, `GitAuth` (basic auth with the token).
- `Detect`: kind `gitea` (and alias `forgejo`), a base URL flag/env like GitLab's (`--gitea-url`, `AEMAN_GITEA_URL`), host
  detection for hosts that contain `gitea`, `forgejo` or `codeberg`.
- Server and CLI wiring the same way GitLab is wired (`cmd/aeman/forge.go`, `internal/server`), client id/secret env
  (`AEMAN_GITEA_CLIENT_ID` / `_SECRET`).
- Tests with `httptest` in the style of `forge_test.go` (no network). Docs: `docs/deploy.md` (register an OAuth app in Gitea /
  Forgejo), `docs/api.md` configuration table, the design doc sentence that Gitea "is not built".
- Done when: `make lint test` green, a board signs in through a Gitea OAuth app in a test, and the branch applies cleanly on
  upstream `main` (it is meant to become an upstream draft PR).
- Why it matters: Gitea and Forgejo can themselves sign people in through any OIDC provider, so this step already gives
  single sign-on to teams that run one, without changing aeman's identity model.

## 2. Helm chart — done
Upstream has an unmerged branch `feat/helm-chart` (`charts/aeman/`, last commit 2026-07-16, from before upstream rewrote its
history, so it has no merge base with `main`). Start from its chart files, copied onto a branch from `upstream/main` (say so in
the PR and in the commit message), and bring them up to date with today's flags and env (`docs/api.md` configuration table,
incl. the Gitea ones). Keep the chart at `charts/aeman/`, where upstream put it.
- Deployment (one replica by default; the server's flags from values), Service, optional Ingress, a PersistentVolumeClaim for
  `--data`, probes, non-root security context, resources.
- Secrets only by reference: values name existing Secrets (git token, OAuth client). Drop a template that renders secret
  values from values files, if the old branch has one, and its example values file.
- Drop a template that creates the Namespace (Helm's `--create-namespace` does that).
- `helm lint` and `helm template` in CI: a separate workflow file under `.github/workflows/`; do not edit `ci.yml`.
- Docs: a Kubernetes section in `docs/deploy.md`.
- Done when: `helm lint` clean, `helm template` renders with defaults and with an Ingress, chart version and app version are
  separate fields.

## 3. CI: golangci-lint fails on the current Go 1.27 patch — done
`ci.yml` pins golangci-lint v2.13.2 and `setup-go` installs the newest Go 1.27 patch; the linter cannot read its export data
(`could not import internal/goarch … export data version 5 is greater than maximum supported version 4`), so the
`golangci-lint` job fails on `main` with no code change (upstream's last green run: 2026-10-07).
- Find the smallest fix that keeps CI reproducible: a golangci-lint release built with that Go (check its release notes),
  or pin the Go patch in both jobs. Keep every action pinned by commit SHA.
- Fix any new lint findings the newer linter reports, in the same PR only if they are few and mechanical; otherwise list them.
- Done when: all `ci.yml` jobs are green on the PR. This is meant for upstream as is.

## 4. Generic OIDC sign-in — next
Sign people in through any OpenID Connect provider (Authentik, Keycloak, Zitadel, Dex, …) and decide their rights from the
provider's groups. The git remote stays a forge (any of the three) reached only with the server's credential. Decision taken
by the fork's architect so the work can go ahead; it is offered upstream as a draft and may be reshaped there.

Where it plugs in: `internal/server/access.go` already has the `domainAccess` interface (`rights`, `readers`). OIDC is a new
implementation of it plus a sign-in flow; the domain, the board service, the storage and the board views stay untouched.

### Configuration (flags and env, mirrored in `docs/api.md`)
- `--oidc-issuer` / `AEMAN_OIDC_ISSUER` turns the mode on. `AEMAN_OIDC_CLIENT_ID` / `AEMAN_OIDC_CLIENT_SECRET`. It is
  refused together with any forge OAuth pair (one sign-in per server), and it needs `AEMAN_BASE_URL` and a server git token.
- `AEMAN_OIDC_SCOPES` (default `openid profile email groups`), `AEMAN_OIDC_LOGIN_CLAIM` (default `preferred_username`),
  `AEMAN_OIDC_GROUPS_CLAIM` (default `groups`).
- `--oidc-access <domain>=<group>:<read|write>` (repeatable; env `AEMAN_OIDC_ACCESS`, comma-separated). `write` implies
  `read`; several rules for one domain add up; `*` as the domain means every configured domain. **Deny by default:** a domain
  with no rule matching the visitor is invisible to them, and a visitor with no readable domain is refused after sign-in.

### Sign-in
- Discovery from `<issuer>/.well-known/openid-configuration`; the `issuer` in the document must equal the configured one;
  https only (plain http allowed for loopback, for tests).
- Authorization-code flow with PKCE (S256), `state` and `nonce`, reusing the existing state cookie and callback handling.
- Verify the ID token (signature from the provider's JWKS, `iss`, `aud`, `exp`, `nonce`). Use a maintained library
  (`github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2`) rather than hand-rolled JWT code; say in the PR why it is worth the
  dependency. Login, name, email and picture come from the ID token or the userinfo endpoint; groups from the configured
  claim (ID token first, else userinfo).
- The MCP OAuth path (dynamic client registration, `pendingAuth`) must sign in through OIDC the same way as the browser.

### Rights and people
- `rights(token, login)`: groups → `domainRights` by the rules above, cached for `accessTTL` like the forge answer. When the
  cache expires the groups are asked again (userinfo with the session's access token, refreshed with the refresh token when
  needed); a 401 there ends the session. So removing someone from a group takes effect within `accessTTL`.
- `readers(domain, logins)`: answered from a directory of people who have signed in (login, name, avatar, groups, last
  sign-in), kept in the session file next to the sessions and rewritten the same way. Someone who never signed in is not in
  the directory, so cannot be assigned yet; say so in the docs. The directory never holds tokens.
- `/api/config` tells the web app the provider's display name (`AEMAN_OIDC_NAME`, default "SSO") for the sign-in button.

### Tests (first) and docs
- An `httptest` OIDC provider (discovery, JWKS, token, userinfo) in the style of `gitea_oauth_test.go`: a full browser
  sign-in; a bad `iss`/`aud`/`nonce`/signature refused; deny by default; read vs write rules; `*`; a group removed at the
  provider loses the domain after `accessTTL`; a revoked session (userinfo 401) ends; `readers` from the directory;
  refusal of OIDC together with a forge OAuth pair; the MCP sign-in path.
- New rows in `docs/design/behavior-matrix.md`; `docs/deploy.md` "Sign in with an OIDC provider" (provider setup, a groups
  claim example, the access rules); `docs/api.md` configuration table; `docs/design/git-backend.md` where it says identity
  comes from the forge.
- Done when: CI green, the sign-in test passes end to end, and nothing under `pkg/` changed.

## 5. Service tokens for agents and other non-interactive clients
Today every API and MCP caller is a browser session (or an MCP client that went through the browser OAuth flow), so a
service that works the board for an agent account has no credential to use. Add static service tokens.
- `AEMAN_SERVICE_TOKENS_FILE`: a file (mounted from a Secret) with one entry per line: `<login> <sha256-hex of the token>`
  and, in OIDC mode, `groups=<g1,g2>`. The server holds hashes only; a token itself is never logged or stored.
- `aeman token new --login <login>` prints a fresh random token (prefix `aeman_svc_`, ≥ 32 random bytes) and the line to add.
- `Authorization: Bearer aeman_svc_…` on `/api/v1` and `/mcp` acts as that login. Rights are decided the same way as for a
  person: forge mode — the server's credential asks the forge whether that login can read/write each domain; OIDC mode —
  the line's groups through the `--oidc-access` rules. Constant-time comparison; an unknown token is 401
  (`notAuthenticated`); the file is re-read when it changes.
- Commits made with a service token are authored with its login, like a person's.
- Tests first (both modes, unknown/removed token, rights, file reload, the MCP path); docs in `docs/api.md`
  ("Authentication and access") and `docs/deploy.md`; a behaviour-matrix row. Chart: an optional `serviceTokens.existingSecret`.
- Done when: CI green and an API call with a service token creates a card authored by its login in a test.
