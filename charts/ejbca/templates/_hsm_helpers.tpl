{{/*
Define HSM container image with versions
*/}}
{{- define "ejbca.hsmImage" -}}
{{- if .Values.hsm.image  }}
{{- printf .Values.hsm.image }}
{{- else if .Values.hsm.softhsm.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-softhsm/images/hsm-driver-softhsm:1.0.8" }}
{{- else if .Values.hsm.luna.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-luna7/images/hsm-driver-luna7:0.1.3" }}
{{- else if .Values.hsm.utimaco.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-utimaco/images/hsm-driver-utimaco:0.1.3" }}
{{- else if .Values.hsm.nshield.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-nshield/images/hsm-driver-nshield:latest" }}
{{- end }}
{{- end -}}

{{/*
Enable individual sidecars: SoftHSM
*/}}
{{- define "ejbca.hsm.sidecar.softhsm" -}}
{{- if .Values.hsm.softhsm.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  env:
  - name: SOFTHSM2_LOG_LEVEL
    value: {{ .Values.hsm.softhsm.logLevel }}
  {{- if .Values.hsm.softhsm.tokenPersistentVolumeClaim }}
  volumeMounts:
  - name: tokens
    mountPath: /mnt/tokens
  {{- end }}
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.softhsm" -}}
{{- if .Values.hsm.softhsm.tokenPersistentVolumeClaim }}
- name: tokens
  persistentVolumeClaim:
    claimName: {{ .Values.hsm.softhsm.tokenPersistentVolumeClaim }}
{{- end }}
{{- end -}}
