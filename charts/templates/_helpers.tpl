{{/*
Define the EJBCA deployment parameters
*/}}
{{- define "ejbca-community-helm.ejbcaDeploymentParameters" -}}
{{- if .Values.ejbca.useEphemeralH2Database }}
- name: DATABASE_JDBC_URL
  value: "jdbc:h2:mem:ejbcadb;DB_CLOSE_DELAY=-1"
{{- else if .Values.ejbca.useH2Persistence }}
- name: DATABASE_JDBC_URL
  value: "jdbc:h2:/mnt/persistent/ejbcadb;DB_CLOSE_DELAY=-1"
{{- end }}
{{- if hasKey .Values.ejbca "env" }}
{{- range $key, $value := .Values.ejbca.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- if hasKey .Values.ejbca "envRaw" }}
{{ toYaml .Values.ejbca.envRaw }}
{{- end }}
{{- end }}

{{/*
Define port that EJBCA redirects for HTTPS
*/}}
{{- define "ejbca-community-helm.ejbcaHttpsPort" -}}
{{- if .Values.nginx.enabled }}
{{- .Values.nginx.service.httpsPort }}
{{- else if .Values.services.directHttp.enabled }}
{{- .Values.services.directHttp.httpsPort }}
{{- else }}
{{- printf "443" }}
{{- end }}
{{- end }}

{{/*
Define port that EJBCA redirects for HTTP
*/}}
{{- define "ejbca-community-helm.ejbcaPubhttpPort" -}}
{{- if .Values.nginx.enabled }}
{{- .Values.nginx.service.httpPort }}
{{- else if .Values.services.directHttp.enabled }}
{{- .Values.services.directHttp.httpPort }}
{{- else }}
{{- printf "80" }}
{{- end }}
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "ejbca-community-helm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ejbca-community-helm.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ejbca-community-helm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ejbca-community-helm.labels" -}}
helm.sh/chart: {{ include "ejbca-community-helm.chart" . }}
{{ include "ejbca-community-helm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ejbca-community-helm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ejbca-community-helm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ejbca-community-helm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ejbca-community-helm.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
