{{/* Chart name. */}}
{{- define "aeman.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "aeman.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Chart label. */}}
{{- define "aeman.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "aeman.labels" -}}
helm.sh/chart: {{ include "aeman.chart" . }}
{{ include "aeman.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. */}}
{{- define "aeman.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aeman.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* The image reference: the tag defaults to "v" + appVersion. */}}
{{- define "aeman.image" -}}
{{- $tag := .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
The forge kind as the env variables spell it: forgejo is the Gitea adapter
under another name, so it reads the Gitea variables.
*/}}
{{- define "aeman.forgeEnvName" -}}
{{- $kind := lower .Values.forge.kind }}
{{- if eq $kind "forgejo" }}GITEA{{ else }}{{ upper $kind }}{{ end }}
{{- end }}

{{/*
The variable of one repository's own token, after the server's rule: the
domain upper-cased, anything but a letter or a digit an underscore.
*/}}
{{- define "aeman.repoTokenEnv" -}}
{{- printf "AEMAN_GIT_TOKEN_%s" (regexReplaceAll "[^A-Z0-9]" (upper .) "_") }}
{{- end }}

{{/* The claim mounted at --data. */}}
{{- define "aeman.claimName" -}}
{{- .Values.persistence.existingClaim | default (printf "%s-data" (include "aeman.fullname" .)) }}
{{- end }}

{{/* Settings the server would refuse at start, refused at render instead. */}}
{{- define "aeman.validate" -}}
{{- $kinds := list "" "github" "gitlab" "gitea" "forgejo" }}
{{- if not (has (lower .Values.forge.kind) $kinds) }}
{{- fail (printf "forge.kind must be one of github, gitlab, gitea, forgejo (got %q)" .Values.forge.kind) }}
{{- end }}
{{- range .Values.repos }}
{{- if or (not .name) (not .url) }}
{{- fail "repos: every entry needs a name and a url" }}
{{- end }}
{{- end }}
{{- if and .Values.forge.url (not (has (lower .Values.forge.kind) (list "gitlab" "gitea" "forgejo"))) }}
{{- fail "forge.url needs forge.kind gitlab, gitea or forgejo" }}
{{- end }}
{{- if .Values.oauth.existingSecret }}
{{- if not .Values.forge.kind }}
{{- fail "oauth.existingSecret needs forge.kind: it picks the AEMAN_<FORGE>_CLIENT_ID/_SECRET pair" }}
{{- end }}
{{- if not .Values.baseUrl }}
{{- fail "oauth.existingSecret needs baseUrl: the forge redirects to <baseUrl>/auth/callback" }}
{{- end }}
{{- end }}
{{- if and .Values.githubApp.id (not .Values.githubApp.existingSecret) }}
{{- fail "githubApp.id needs githubApp.existingSecret holding the App's private key" }}
{{- end }}
{{- if and .Values.githubApp.existingSecret (not .Values.githubApp.id) }}
{{- fail "githubApp.existingSecret needs githubApp.id" }}
{{- end }}
{{- if gt (int .Values.replicaCount) 1 }}
{{- fail "replicaCount: aeman runs as one replica (it locks its --data directory)" }}
{{- end }}
{{- end }}

{{/* AEMAN_REPOS: name=url pairs, comma-separated, the primary first. */}}
{{- define "aeman.repos" -}}
{{- $pairs := list }}
{{- range .Values.repos }}
{{- $pairs = append $pairs (printf "%s=%s" .name .url) }}
{{- end }}
{{- join "," $pairs }}
{{- end }}
