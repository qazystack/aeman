# Deploying aeman (self-hosted, multi-user)

Runs aeman behind Caddy, which terminates TLS with an automatic Let's Encrypt certificate. Each visitor signs in with the forge the board repositories live on — GitHub, GitLab (gitlab.com or self-hosted) or Gitea / Forgejo — and acts with **their own** token; the server fetches and pushes with its own (`AEMAN_GIT_TOKEN`).

```
browser ──HTTPS──► Caddy (:443, auto-TLS) ──http──► aeman:8765
```

## 1. Register an OAuth application

One forge per instance: register the application at GitHub, GitLab **or** Gitea / Forgejo and fill in that pair of variables only. On all of them, the callback is `<AEMAN_BASE_URL>/auth/callback`.

### GitHub — a GitHub App (recommended)

A GitHub App gives both halves at once: the sign-in (its Client ID/secret work in the same OAuth endpoints, and the consent screen shows the app's per-repository permissions instead of `repo` — full access to every private repository the person has), and the **server credential without a PAT** — the server signs a JWT with the app's private key and mints installation tokens, scoped to the repositories the app is installed on, renewed automatically. Nothing to issue by hand, nothing that quietly expires in a `.env` file.

GitHub → the organisation's **Settings** → Developer settings → **GitHub Apps** → **New GitHub App**:

- **Homepage URL:** `https://aeman.example.com`
- **Callback URL:** `https://aeman.example.com/auth/callback`; keep **Expire user authorization tokens** on, and leave **Request user authorization (OAuth) during installation** OFF — aeman starts its own sign-in from its login button, and this option makes GitHub start one after every installation, landing people on the callback out of the blue (the server treats an installation-signed callback as the setup event, but the extra round trip serves nobody)
- **Webhook:** off
- **Setup URL (optional):** `https://aeman.example.com/auth/setup`, with **Redirect on update** checked — after someone installs the app, GitHub sends them back to the board, which, if it was still waiting for that installation, tries the repositories again at once
- **Repository permissions:** **Contents: Read and write**, **Metadata: Read-only** (automatic)
- **Where can this app be installed:** Any account, if boards of other organisations will use it

Give the app a face while you are there: under **Display information** upload [`docs/assets/app-icon.png`](assets/app-icon.png) — the aeman logo rendered at 512×512, the shape GitHub asks for (PNG, at least 200×200) — and pick a badge background (the logo sits on white, so any light colour works).

Generate a **client secret** and a **private key** (a `.pem` download). Then **install the app**: on each organisation the board's repositories live in, choosing those repositories.

The sign-in and the server credential are configured independently: people may sign in through an **OAuth App** (below) while the GitHub App stays the server credential, and the PAT still disappears. The five variables: `AEMAN_GITHUB_CLIENT_ID` / `AEMAN_GITHUB_CLIENT_SECRET` (sign-in), `AEMAN_GITHUB_APP_ID` (the numeric App ID) and `AEMAN_GITHUB_APP_KEY` (the key PEM, or base64 of it — a `.env` file cannot hold a multiline value) or `AEMAN_GITHUB_APP_KEY_FILE` (a path). With the App configured, `AEMAN_GIT_TOKEN*` is not needed; a repository that names its own token keeps it, the App covers the rest.

### GitHub — an OAuth App (the static-token alternative)

GitHub → Settings → Developer settings → **OAuth Apps** → **New OAuth App**:

- **Homepage URL:** `https://aeman.example.com`
- **Authorization callback URL:** `https://aeman.example.com/auth/callback`

Generate a client secret. Keep the **Client ID** and **Client secret** — they become `AEMAN_GITHUB_CLIENT_ID` / `AEMAN_GITHUB_CLIENT_SECRET`. In this mode the sign-in asks for the `repo` scope (a private board repository is invisible to a token without it — and the consent screen therefore offers access to everything private the person has), and the server needs its own PAT: `AEMAN_GIT_TOKEN`, or one per repository.

### GitLab

GitLab → User Settings (or a group's **Settings**, or the **Admin area**) → **Applications** → **Add new application**:

- **Name:** `aeman`
- **Redirect URI:** `https://aeman.example.com/auth/callback`
- **Confidential:** yes
- **Scopes:** `read_user`, `read_api`

Save it. Keep the **Application ID** and **Secret** — they become `AEMAN_GITLAB_CLIENT_ID` / `AEMAN_GITLAB_CLIENT_SECRET`. On a self-hosted GitLab also set `AEMAN_GITLAB_URL` to its base URL (`https://gitlab.example.com`); on gitlab.com nothing more is needed.

### Gitea / Forgejo

One adapter serves both: Forgejo keeps the Gitea API v1. Gitea or Forgejo → **Settings** → **Applications** → **Manage OAuth2 Applications** (for an instance-wide application: **Site Administration** → **Integrations** → **Applications**):

- **Application name:** `aeman`
- **Redirect URIs:** `https://aeman.example.com/auth/callback`
- **Confidential client:** yes

Save it. Keep the **Client ID** and **Client Secret** — they become `AEMAN_GITEA_CLIENT_ID` / `AEMAN_GITEA_CLIENT_SECRET`. Set `AEMAN_GITEA_URL` to the instance's base URL (`https://gitea.example.com`, including the subpath if it is served under one) unless the repository's host already contains `gitea`, `forgejo` or `codeberg`; `AEMAN_FORGE=forgejo` (instead of `gitea`) only changes the name the sign-in page shows. The sign-in asks for `read:user read:repository` — the visitor's token never pushes; an instance older than scoped OAuth tokens ignores the parameter. `AEMAN_GIT_TOKEN` is an access token of an account that can write the board repositories (Settings → Applications → **Generate New Token**, with repository read and write and user read). Gitea and Forgejo can themselves sign people in through an external OIDC provider, so a team that runs one gets single sign-on to the board through it.

## 2. DNS and firewall

- Add a DNS **A record**: `aeman.example.com` → your server IP (DNS-only / not proxied, so Caddy can solve the ACME challenge).
- Open inbound TCP **80** and **443** on the server.

## 3. Configure and run

```sh
git clone https://github.com/aenix-io/aeman.git
cd aeman
cp .env.example .env
# fill AEMAN_REPOS, AEMAN_GIT_TOKEN, AEMAN_BASE_URL, AEMAN_DOMAIN and ONE pair:
#   AEMAN_GITHUB_CLIENT_ID / _SECRET, or
#   AEMAN_GITLAB_CLIENT_ID / _SECRET (+ AEMAN_GITLAB_URL for a self-hosted GitLab), or
#   AEMAN_GITEA_CLIENT_ID / _SECRET (+ AEMAN_GITEA_URL)
docker compose up -d --build
```

The compose file builds from this checkout. To run a **published** image instead — every release tag is built for `linux/amd64` and `linux/arm64` and pushed to `ghcr.io/aenix-io/aeman` — drop the `build:` block and name the image: `image: ghcr.io/aenix-io/aeman:latest` (or a version, `:v0.29.4`). Upgrading is then `docker compose pull && docker compose up -d`.

`AEMAN_REPOS` names the board's repositories as `name=url`, comma-separated, the primary first — HTTPS clone URLs on the forge, e.g. `aeman-db=https://github.com/acme/aeman-db.git` or `aeman-db=https://gitlab.com/acme/aeman-db.git`. `AEMAN_GIT_TOKEN` is the server's own credential for them (fetch, push, and the membership checks behind the assignee pickers); it is required in this mode. An **empty** repository becomes a board first, on either forge: `aeman init --repo <url>` — from this directory, `docker compose run --rm aeman init --repo https://gitlab.com/acme/aeman-db.git`. `serve` refuses an unborn remote and names that command.

`AEMAN_GIT_TOKEN` is the server's own credential for all of them. A board whose repositories live in **two organisations** gives each its own instead: `AEMAN_GIT_TOKEN_<NAME>`, named after the domain (upper-cased, anything but a letter or a digit an underscore — `founders` → `AEMAN_GIT_TOKEN_FOUNDERS`). This is what lets each token stay narrow: a fine-grained GitHub token belongs to one organisation, so one token cannot cover repositories in two, and a classic token that could is wider than either repository needs. Pass the variables you use through the compose file's `environment` block.

Caddy issues the certificate on first start (needs DNS + ports 80/443 already in place). Open `https://aeman.example.com`, click **Sign in with GitHub** (or **GitLab**, **Gitea**, **Forgejo**), and you're in.

## Kubernetes (Helm)

The chart at [`charts/aeman`](../charts/aeman) runs the published image (`ghcr.io/aenix-io/aeman`, tag `v` + the chart's `appVersion` unless `image.tag` says otherwise) as **one replica** with a `Recreate` strategy — the process locks its `--data` directory, so two pods on one volume cannot both run — behind a Service, an optional Ingress, and a PersistentVolumeClaim for `--data` (the clones and the session file). It runs as the image's non-root user on a read-only root file system and probes `/api/healthz`; the startup probe allows five minutes for the first clone. The chart's own `version` and the `appVersion` it deploys are separate fields of `Chart.yaml`.

The chart never holds a secret value. Create the Secrets first, in the release's namespace, and name them in the values:

```sh
kubectl create namespace aeman
kubectl -n aeman create secret generic aeman-git --from-literal=token=<server token>
kubectl -n aeman create secret generic aeman-oauth \
  --from-literal=client-id=<client id> --from-literal=client-secret=<client secret>
kubectl -n aeman create secret generic aeman-session --from-literal=session-key=<random string>
```

Then a values file — the settings are the variables above, one key each:

```yaml
repos:                      # AEMAN_REPOS, the primary first
  - name: board
    url: https://github.com/acme/aeman-db.git
forge:
  kind: github              # AEMAN_FORGE; it also picks the client id/secret variables
  url: ""                   # AEMAN_GITLAB_URL / AEMAN_GITEA_URL for a self-hosted forge
baseUrl: https://aeman.example.com
gitToken:
  existingSecret: aeman-git # AEMAN_GIT_TOKEN
oauth:
  existingSecret: aeman-oauth
session:
  existingSecret: aeman-session
ingress:
  enabled: true
  className: nginx
  annotations:
    # The board keeps a WebSocket open (/api/v1/watch).
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
  hosts:
    - host: aeman.example.com
      paths: [{path: /}]
  tls:
    - secretName: aeman-tls
      hosts: [aeman.example.com]
```

```sh
helm install aeman charts/aeman -n aeman -f values.yaml
```

The rest follows the same variables: `repoTokens` gives a repository its own `AEMAN_GIT_TOKEN_<NAME>` (the name derived from the domain by the server's rule), `githubApp.id` with `githubApp.existingSecret` mounts the App's private key as a file for `AEMAN_GITHUB_APP_KEY_FILE`, `serviceTokens.existingSecret` (the file under `serviceTokens.key`, default `tokens`) mounts the [service tokens](#service-tokens-for-agents-and-bots-optional) file read-only for `AEMAN_SERVICE_TOKENS_FILE` — as a directory, so an edited Secret reaches the pod and the server re-reads it without a restart — and `config`, `timezone`, `scopes`, `extraEnv` and `extraArgs` cover the rest. Settings the server would refuse at start — an OAuth Secret without `forge.kind` or `baseUrl`, a `forge.url` on GitHub, more than one replica — fail the render instead. Without `oauth.existingSecret` the pod runs in the single-user local mode as whoever `AEMAN_GIT_TOKEN` belongs to. `charts/aeman/values.yaml` documents every key; `make chart` lints the chart and checks what it renders.

## Sign in with an OIDC provider (optional)

Instead of the forge, people can sign in through any OpenID Connect provider — Authentik, Keycloak, Zitadel, Dex, … — and the provider's **groups** decide what they may read and write. The forge stays where the repositories live; the server reaches it only with its own credential (`AEMAN_GIT_TOKEN`, a token per repository, or a GitHub App), so that credential must be able to push every repository of the board. The visitor's token is the provider's and never touches git. One sign-in per server: leave every forge `AEMAN_*_CLIENT_ID`/`_SECRET` pair unset.

**At the provider**, create a client (an "application" or "OAuth2/OpenID provider", depending on the product):

- **Type:** confidential, authorization-code flow (aeman adds PKCE S256 and a nonce).
- **Redirect URI:** `https://aeman.example.com/auth/callback`.
- **Scopes:** `openid profile email groups` — or whatever makes the provider put the person's groups in a claim.
- **A groups claim.** Most providers need it switched on: in Keycloak add a *Group Membership* mapper to the client (token claim name `groups`, *Full group path* off); in Authentik the default `profile` scope mapping already sends `groups`; in Dex the `groups` scope does. An ID token then carries something like:

```json
{
  "iss": "https://sso.example.com/realms/eng",
  "preferred_username": "alice",
  "name": "Alice Liddell",
  "groups": ["engineering", "auditors"]
}
```

**In `.env`:**

```sh
AEMAN_OIDC_ISSUER=https://sso.example.com/realms/eng
AEMAN_OIDC_CLIENT_ID=aeman
AEMAN_OIDC_CLIENT_SECRET=…
# <domain>=<group>:<read|write>, comma-separated; * is every domain
AEMAN_OIDC_ACCESS=aeman-db=engineering:write,*=auditors:read
AEMAN_OIDC_NAME=Corp SSO          # the sign-in button; default "SSO"
```

The issuer must be https, and its discovery document (`<issuer>/.well-known/openid-configuration`) must name exactly that issuer. `AEMAN_OIDC_LOGIN_CLAIM` (default `preferred_username`) is the claim that becomes the login — what cards are assigned to and commits are attributed to; `AEMAN_OIDC_GROUPS_CLAIM` (default `groups`) the one groups are read from, the ID token first and userinfo when the ID token leaves it out.

**The access rules.** Each rule gives one group `read` or `write` on one domain (the names in `AEMAN_REPOS`), or on every domain with `*`. `write` implies `read`, and rules for the same domain add up. **Access is denied by default:** a domain no rule opens to a person is invisible to them, and a person no rule opens any domain to is turned away right after signing in. As with the forge, a person who cannot read the primary repository has no board. A rule naming a domain the board does not have stops the server at start-up rather than quietly denying everyone.

**Taking access away.** The answer is trusted for a minute. After that aeman asks the provider again (userinfo, with the session's access token, renewed with the refresh token when needed), so taking someone out of a group takes effect within a minute, and revoking their session at the provider signs them out of aeman.

**Who can be assigned.** aeman learns people from the provider when they sign in and keeps a directory of them — login, name, avatar, groups, last sign-in — in `AEMAN_SESSION_FILE`, next to the sessions (it never holds a token). The assignee pickers offer the people in it whose groups can read the card's domain. **Someone who has never signed in is not in the directory, so they cannot be assigned yet**: ask them to sign in once.

MCP clients connecting to `https://aeman.example.com/mcp` sign in through the same provider.

## Service tokens for agents and bots (optional)

A client that cannot sign in through a browser — an agent with an account of its own, a bot — uses a **service token**: `Authorization: Bearer aeman_svc_…` on `/api/v1` or `/mcp`, acting as a login you name. Make one with

```sh
aeman token new --login agent-bot            # the forge mode
aeman token new --login agent-bot --groups engineering   # the OIDC mode
```

It prints the token — hand it to the client; it is not shown again — and a line such as `agent-bot 3f…9a groups=engineering`. Put the lines in a file the server reads (in Kubernetes, a Secret mounted as a file) and point `AEMAN_SERVICE_TOKENS_FILE` at it. The file holds only the SHA-256 of each token, never the token. It is re-read when it changes: add a line and the token works on the next request; remove it and the token stops working on the next request, with no restart. A file that stops parsing accepts no service token until it is fixed.

What the token may do is decided like a person's rights. **Forge mode:** the login must be a real account on the forge with access to the repositories — the server asks the forge with its own credential (GitHub: a collaborator with read or write; GitLab: a member, Reporter reads, Developer writes; Gitea / Forgejo: a collaborator, owner or organisation team member with read or write). **OIDC mode:** the login need not exist anywhere; the line's `groups=` go through the `AEMAN_OIDC_ACCESS` rules, and a line no rule opens a domain to is refused. Either way the commits it makes are authored with its login.

## Choosing the forge (optional)

`AEMAN_FORGE=github|gitlab|gitea|forgejo` names the forge explicitly. Unset, it follows the primary repository's host: `github.com` → GitHub, a host containing `gitlab` → GitLab, a host containing `gitea` → Gitea, one containing `forgejo` or `codeberg` → Forgejo, anything else → GitHub unless `AEMAN_GITLAB_URL` or `AEMAN_GITEA_URL` is set (both set with no `AEMAN_FORGE` is refused). A self-hosted GitLab on a host without `gitlab` in its name therefore needs `AEMAN_GITLAB_URL` (or `AEMAN_FORGE=gitlab`, in which case the URL defaults to `https://<host of the primary repository>`); a Gitea or Forgejo likewise needs `AEMAN_GITEA_URL` or `AEMAN_FORGE=gitea`/`forgejo`.

## Lock to one board (optional)

To pin every visitor to a single project and hide the board picker, set in `.env`:

```sh
AEMAN_OWNER=acme
AEMAN_BOARD=37
AEMAN_LOCK_BOARD=true
```

A user whose token can't read that board sees an access-denied screen rather than the board.

## Notes

- **Who sees what.** A visitor's own token decides per repository (with an OIDC provider, the groups decide — see [above](#sign-in-with-an-oidc-provider)). GitHub: the repository's `permissions` — `pull` reads, `push`/`maintain`/`admin` write. GitLab: the project's access level — Reporter (20) reads, Developer (30) and above write; a Guest sees the project but not its board; public and internal projects read for anyone signed in. Gitea / Forgejo: the repository's `permissions` — `pull` reads, `push`/`admin` write; a public repository reads for anyone. The assignee pickers list the people who can read the repository: on GitHub each login's collaborator permission, asked with the server token; on GitLab the project's member list (inherited group members included), which also supplies display names and avatars; on Gitea / Forgejo each login's collaborator permission (ownership and organisation teams included), whose answer supplies them too.
- **Sessions & the session store.** `AEMAN_SESSION_FILE` (on the `aeman_sessions` volume) always persists the dynamic MCP client registry. Sessions — the visitors' forge tokens — are written there only when `AEMAN_SESSION_KEY` is set, encrypted with it (AES-256-GCM); then restarts and redeploys keep users signed in and MCP tokens live. Without the key, sessions stay in memory and a restart signs everyone out — no plaintext token ever touches disk either way. Keep the key stable (changing or losing it just signs everyone out) and store it outside the session volume so a leak of that volume alone exposes nothing. GitHub's classic OAuth App tokens don't expire, so a session simply lasts up to 14 days.
- **Scopes:** `AEMAN_SCOPES` overrides what the sign-in asks for; the default is `repo` on GitHub (a GitHub App ignores the parameter — its permissions come from the installation) `read_user read_api` on GitLab and `read:user read:repository` on Gitea / Forgejo.
- **Cert storage:** the `caddy_data` volume persists issued certificates across restarts.
- **Local single-user mode:** without a client id/secret pair the binary runs as a single-user local tool on the identity of whoever its token belongs to — the forge's token variables, then the OS keychain that `aeman login` writes, then the forge CLI signed in on the machine (`gh` on GitHub, `glab` on GitLab; Gitea / Forgejo have no such tool, so there it is `GITEA_TOKEN`/`FORGEJO_TOKEN` or `aeman login`). See [api.md](api.md#aeman-login).
- **Behind Cloudflare Tunnel instead of Caddy?** Drop the `caddy` service, add a `cloudflared` service with your tunnel token, and route the public hostname to `http://aeman:8765`; keep `AEMAN_BASE_URL` pointed at the public HTTPS URL.
