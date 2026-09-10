{{/*
Name helpers, in the shape `helm create` produces, so that anyone who has read
another chart can read this one.
*/}}

{{- define "asterius.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "asterius.fullname" -}}
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

{{- define "asterius.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "asterius.labels" -}}
helm.sh/chart: {{ include "asterius.chart" . }}
{{ include "asterius.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: openid-provider
app.kubernetes.io/part-of: asterius
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "asterius.selectorLabels" -}}
app.kubernetes.io/name: {{ include "asterius.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "asterius.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "asterius.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The image reference. A digest wins over a tag: a tag can be moved under you and
a digest cannot, and once the release workflow signs images the digest is what
a signature is about.
*/}}
{{- define "asterius.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
The name of the ConfigMap holding asterius.toml.
*/}}
{{- define "asterius.configMapName" -}}
{{- default (printf "%s-config" (include "asterius.fullname" .)) .Values.config.existingConfigMap }}
{{- end }}

{{- define "asterius.secretName" -}}
{{- printf "%s-secrets" (include "asterius.fullname" .) }}
{{- end }}

{{/*
Whether the chart has to create a Secret of its own: true as soon as one
`secrets.*.value` or `database.urlSecret.value` is set. Everything else comes
from Secrets the operator manages.
*/}}
{{- define "asterius.createsSecret" -}}
{{- $create := false }}
{{- range $key := list "kek" "kekPrevious" "adminPassword" "dpopNonceSecret" }}
{{- $entry := index $.Values.secrets $key }}
{{- if and $entry $entry.value (not $entry.existingSecret) }}
{{- $create = true }}
{{- end }}
{{- end }}
{{- if and .Values.database.urlSecret.value (not .Values.database.urlSecret.existingSecret) }}
{{- $create = true }}
{{- end }}
{{- if $create }}true{{- end }}
{{- end }}
