{{- define "afs.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "afs.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "afs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "afs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{- /* Labels without the component, for objects that are not the server pod
(the test pod must not match the Service or the NetworkPolicy). */}}
{{- define "afs.commonLabels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "afs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "afs.labels" -}}
{{ include "afs.commonLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{- define "afs.secretName" -}}
{{- .Values.tokens.existingSecret | default (include "afs.fullname" .) }}
{{- end }}

{{- define "afs.claimName" -}}
{{- .Values.persistence.existingClaim | default (printf "%s-data" (include "afs.fullname" .)) }}
{{- end }}
