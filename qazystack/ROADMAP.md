# Fork roadmap

Order matters: each step is one branch and one PR. Mark a step done here in the PR that implements it.

Upstream is about to rework the domain (new entities such as Initiative and Epic). So the fork does not touch the domain,
the board service or the storage: `pkg/board`, `pkg/boardservice`, `pkg/gitstore`, `pkg/apiserver`, `pkg/mcpserver`, the
board views in `web/`. Work stays at the edges: forges, sign-in, packaging.

## 1. Gitea / Forgejo forge — next
A third adapter in `internal/forge` beside GitHub and GitLab (`docs/design/git-backend.md`, "Forge-agnostic by construction",
already names Gitea as the next adapter). One adapter serves both Gitea and Forgejo (Forgejo keeps the Gitea API v1).
- `internal/forge/gitea.go`: OAuth2 authorize/token URLs (`/login/oauth/authorize`, `/login/oauth/access_token`), scopes for
  user and repository read/write, `User` (`GET /api/v1/user`), `Access` (`GET /api/v1/repos/{owner}/{repo}`, `permissions`),
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

## 2. Helm chart
`deploy/helm/aeman/`: Deployment (one replica by default, the binary's flags from values), Service, optional Ingress, a
PersistentVolumeClaim for `--data`, Secret references (existing secret names in values, never secret values in the chart),
probes, non-root security context, resources. `helm lint` and `helm template` in CI (a separate workflow file under
`.github/workflows/`, do not edit `ci.yml`). Docs: a Kubernetes section in `docs/deploy.md`.
- Done when: `helm lint` clean, `helm template` renders with defaults and with an Ingress, the chart version and the app
  version are separate fields.

## 3. Generic OIDC sign-in — waiting for a decision
Today identity and repository rights both come from the forge. Signing in through a plain OIDC provider needs a decision on
where rights come from (OIDC groups → domains, or still the forge). Discussed with upstream first; do not implement.
