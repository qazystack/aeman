#!/usr/bin/env bash
# Lints the chart and renders it with the default values and with each
# ci/*-values.yaml, then checks what the rendering must and must not contain.
# Run from the repository root: charts/test.sh (needs helm 3).
set -euo pipefail

chart=charts/aeman
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { helm template aeman "$chart" "$@"; }
has() { grep -qF -- "$2" <<<"$1" || fail "$3: expected '$2'"; }
lacks() { ! grep -qF -- "$2" <<<"$1" || fail "$3: unexpected '$2'"; }
refused() {
  local why=$1 msg=$2; shift 2
  local out
  if out=$(render "$@" 2>&1); then fail "$why: rendered, expected a refusal"; fi
  grep -qF -- "$msg" <<<"$out" || fail "$why: refused without '$msg': $out"
}

helm lint --strict "$chart"
for v in "$chart"/ci/*-values.yaml; do helm lint --strict "$chart" -f "$v"; done

# Defaults: one Deployment, its Service and claim — no Ingress, and never a
# Secret or a Namespace (secrets are referenced, --create-namespace makes one).
out=$(render)
has "$out" "kind: Deployment" defaults
has "$out" "kind: Service" defaults
has "$out" "kind: PersistentVolumeClaim" defaults
lacks "$out" "kind: Ingress" defaults
lacks "$out" "kind: Secret" defaults
lacks "$out" "kind: Namespace" defaults
lacks "$out" "AEMAN_REPOS" "defaults (no repos)"
has "$out" "replicas: 1" defaults
has "$out" "type: Recreate" defaults
has "$out" 'image: "ghcr.io/aenix-io/aeman:v' "defaults (tag from appVersion)"
has "$out" "readOnlyRootFilesystem: true" defaults
has "$out" "runAsNonRoot: true" defaults
has "$out" "path: /api/healthz" defaults
has "$out" 'value: "/data/sessions.json"' defaults

# GitHub with an App, a per-repository token and an Ingress.
out=$(render -f "$chart/ci/github-oauth-values.yaml")
has "$out" 'value: "board=https://github.com/example/aeman-db.git,founders-x=https://github.com/example-two/aeman-founders.git"' github
has "$out" "name: AEMAN_GITHUB_CLIENT_ID" github
has "$out" "name: AEMAN_GITHUB_CLIENT_SECRET" github
has "$out" "name: AEMAN_GITHUB_APP_ID" github
has "$out" "value: /etc/aeman/github-app/private-key.pem" github
has "$out" "name: AEMAN_GIT_TOKEN_FOUNDERS_X" "github (token name after the server's rule)"
has "$out" "name: AEMAN_SESSION_KEY" github
has "$out" "name: AEMAN_SYNC_INTERVAL" github
has "$out" 'value: "Europe/Berlin"' github
has "$out" "kind: Ingress" github
has "$out" "secretName: aeman-tls" github
has "$out" "ingressClassName: nginx" github
! grep -qE "name: AEMAN_GIT_TOKEN$" <<<"$out" || fail "github: a static AEMAN_GIT_TOKEN beside the App"
lacks "$out" "kind: Secret" github

# Forgejo reads the Gitea variables; an existing claim is mounted, not made.
out=$(render -f "$chart/ci/gitea-values.yaml")
has "$out" 'value: "forgejo"' gitea
has "$out" "name: AEMAN_GITEA_URL" gitea
has "$out" "name: AEMAN_GITEA_CLIENT_ID" gitea
has "$out" "name: AEMAN_GIT_TOKEN" gitea
has "$out" "claimName: aeman-data" gitea
lacks "$out" "kind: PersistentVolumeClaim" gitea
lacks "$out" "AEMAN_GITHUB" gitea

# What the server would refuse at start is refused at render.
refused "unknown forge" "forge.kind must be one of" --set forge.kind=bitbucket
refused "oauth without a forge" "needs forge.kind" --set oauth.existingSecret=x --set baseUrl=https://a.example.com
refused "oauth without baseUrl" "needs baseUrl" --set oauth.existingSecret=x --set forge.kind=github
refused "forge url on github" "forge.url needs forge.kind" --set forge.url=https://a.example.com
refused "app without its key" "needs githubApp.existingSecret" --set githubApp.id=1
refused "two replicas" "one replica" --set replicaCount=2

echo "chart OK"
