{{- define "brrpolice.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "brrpolice.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "brrpolice.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "brrpolice.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "brrpolice.config" -}}
{{- tpl (toToml .Values.config) . -}}
{{- end -}}

{{- define "brrpolice.selectorLabels" -}}
app.kubernetes.io/name: {{ include "brrpolice.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/controller: brrpolice
{{- end -}}

{{- define "brrpolice.labels" -}}
{{ include "brrpolice.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{- define "brrpolice.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "brrpolice.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "brrpolice.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Whether a StatefulSet owns the data PVC through a volumeClaimTemplate. */}}
{{- define "brrpolice.dataClaimTemplate" -}}
{{- if and (eq .Values.controller.type "statefulset") .Values.persistence.enabled (not .Values.persistence.existingClaim) -}}
true
{{- end -}}
{{- end -}}

{{/* PVC spec shared by the standalone PVC and the StatefulSet volumeClaimTemplate. */}}
{{- define "brrpolice.dataClaimSpec" -}}
accessModes:
  {{- toYaml .Values.persistence.accessModes | nindent 2 }}
{{- if ne .Values.persistence.storageClass nil }}
storageClassName: {{ .Values.persistence.storageClass | quote }}
{{- end }}
resources:
  requests:
    storage: {{ .Values.persistence.size | quote }}
{{- with .Values.persistence.dataSourceRef }}
dataSourceRef:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
