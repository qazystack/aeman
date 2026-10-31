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

## 3. CI: golangci-lint fails on the current Go 1.27 patch — next
`ci.yml` pins golangci-lint v2.13.2 and `setup-go` installs the newest Go 1.27 patch; the linter cannot read its export data
(`could not import internal/goarch … export data version 5 is greater than maximum supported version 4`), so the
`golangci-lint` job fails on `main` with no code change (upstream's last green run: 2026-10-07).
- Find the smallest fix that keeps CI reproducible: a golangci-lint release built with that Go (check its release notes),
  or pin the Go patch in both jobs. Keep every action pinned by commit SHA.
- Fix any new lint findings the newer linter reports, in the same PR only if they are few and mechanical; otherwise list them.
- Done when: all `ci.yml` jobs are green on the PR. This is meant for upstream as is.

## 4. Generic OIDC sign-in — waiting for a decision
Today identity and repository rights both come from the forge. Signing in through a plain OIDC provider needs a decision on
where rights come from (OIDC groups → domains, or still the forge). Discussed with upstream first; do not implement.
