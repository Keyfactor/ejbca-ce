{{/*
Define HSM container image with versions
*/}}
{{- define "ejbca.hsmImage" -}}
{{- if .Values.hsm.image  }}
{{- .Values.hsm.image }}
{{- else if .Values.hsm.softhsm.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-softhsm/images/hsm-driver-softhsm:1.1.0" }}
{{- else if .Values.hsm.luna.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-luna7/images/hsm-driver-luna7:0.5.0" }}
{{- else if .Values.hsm.dpod.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-dpod/images/hsm-driver-dpod:0.1.0" }}
{{- else if .Values.hsm.utimaco.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-utimaco/images/hsm-driver-utimaco:0.4.0" }}
{{- else if .Values.hsm.nshield.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-nshield/images/hsm-driver-nshield:0.5.0" }}
{{- else if .Values.hsm.awsCloudHsm.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-cloudhsm5/images/hsm-driver-cloudhsm5:0.2.0" }}
{{- else if .Values.hsm.lunatct.enabled }}
{{- printf "keyfactor.jfrog.io/dev-oci/keyfactor-commons/hsm-driver-safenetat/images/hsm-driver-safenetat:1.1.0" }}
{{- end }}
{{- end -}}

{{/*
Enable individual sidecars and volumes: SoftHSM
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

{{/*
Enable individual sidecars and volumes: Luna
*/}}
{{- define "ejbca.hsm.sidecar.luna" -}}
{{- if .Values.hsm.luna.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  env:
    - name: SERVER_NAME
      value: {{ .Values.hsm.luna.server_name }}
    - name: CKLOG2_ENABLED
      value: {{ quote .Values.hsm.luna.CKLOG2_ENABLED }}
    - name: PROTECTED_AUTHENTICATION_PATH_FLAG_STATUS
      value: {{ quote .Values.hsm.luna.PROTECTED_AUTHENTICATION_PATH_FLAG_STATUS }}
  volumeMounts:
    - name: hsm-luna-configmap-servercert
      mountPath: /opt/luna/certs-server/server.pem
      subPath: server.pem
    - name: hsm-luna-configmap-client-cert
      mountPath: /opt/luna/certs-client/dockerlunaclient.pem
      subPath: dockerlunaclient.pem
    - name: hsm-luna-secret-client-key
      mountPath: /opt/luna/certs-client/dockerlunaclientKey.pem
      subPath: dockerlunaclientKey.pem
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.luna" -}}
- name: hsm-luna-configmap-servercert
  configMap:
    name: {{ .Values.hsm.luna.credentials.certificates.configMap }}
    items:
      - key: "server.pem"
        path: "server.pem"
- name: hsm-luna-configmap-client-cert
  configMap:
    name: {{ .Values.hsm.luna.credentials.certificates.configMap }}
    items:
      - key: "dockerlunaclient.pem"
        path: "dockerlunaclient.pem"
- name: hsm-luna-secret-client-key
  secret:
    secretName: {{ .Values.hsm.luna.credentials.privateKey.secret }}
{{- end -}}

{{/*
Enable individual sidecars and volumes: lunatct
Almost same as Luna but allows mounting of /opt/keyfactor/Chrystoki.conf as an alternative (HA setup, important for production)
*/}}
{{- define "ejbca.hsm.sidecar.lunatct" -}}
{{- if .Values.hsm.lunatct.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  env:
    {{- if .Values.hsm.lunatct.server_name }}
    - name: SERVER_NAME
      value: {{ .Values.hsm.lunatct.server_name }}
    {{- end}}
    - name: CKLOG2_ENABLED
      value: {{ quote .Values.hsm.lunatct.CKLOG2_ENABLED }}
    - name: PROTECTED_AUTHENTICATION_PATH_FLAG_STATUS
      value: {{ quote .Values.hsm.lunatct.PROTECTED_AUTHENTICATION_PATH_FLAG_STATUS }}
  volumeMounts:
    - name: hsm-luna-configmap-servercert
      mountPath: /opt/safenetat/certs-server/server.pem
      subPath: server.pem
    - name: hsm-luna-configmap-client-cert
      mountPath: /opt/safenetat/certs-client/dockerlunaclient.pem
      subPath: dockerlunaclient.pem
    - name: hsm-luna-secret-client-key
      mountPath: /opt/safenetat/certs-client/dockerlunaclientKey.pem
      subPath: dockerlunaclientKey.pem
    {{- if .Values.hsm.lunatct.custom_chrystoki_conf_secret }}
    - name: hsm-custom-chrystoki-conf
      mountPath: /opt/keyfactor/Chrystoki.conf
      subPath: Chrystoki.conf
    {{- end}}
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.lunatct" -}}
- name: hsm-luna-configmap-servercert
  configMap:
    name: {{ .Values.hsm.lunatct.credentials.certificates.configMap }}
    items:
      - key: "server.pem"
        path: "server.pem"
- name: hsm-luna-configmap-client-cert
  configMap:
    name: {{ .Values.hsm.lunatct.credentials.certificates.configMap }}
    items:
      - key: "dockerlunaclient.pem"
        path: "dockerlunaclient.pem"
- name: hsm-luna-secret-client-key
  secret:
    secretName: {{ .Values.hsm.lunatct.credentials.privateKey.secret }}
{{- if .Values.hsm.lunatct.custom_chrystoki_conf_secret }}
- name: hsm-custom-chrystoki-conf
  secret:
    secretName: {{ .Values.hsm.lunatct.custom_chrystoki_conf_secret }}
{{- end}}
{{- end -}}

{{/*
Enable individual sidecars and volumes: DPoD
*/}}
{{- define "ejbca.hsm.sidecar.dpod" -}}
{{- if .Values.hsm.dpod.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  volumeMounts:
    - name: hsm-dpod-secret
      mountPath: "/opt/keyfactor/thales/conf/Chrystoki.conf"
      subPath: Chrystoki.conf
    - name: hsm-dpod-secret
      mountPath: "/opt/keyfactor/thales/conf/partition-certificate.pem"
      subPath: partition-certificate.pem
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.dpod" -}}
- name: hsm-dpod-secret
  secret:
    secretName: {{ .Values.hsm.dpod.hsmConfigurationSecret }}
{{- end -}}

{{/*
Enable individual sidecars and volumes: Utimaco
*/}}
{{- define "ejbca.hsm.sidecar.utimaco" -}}
{{- if .Values.hsm.utimaco.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  volumeMounts:
    - name: cs-pkcs11-r3-cfg
      mountPath: /etc/cs_pkcs11_R3.cfg
      subPath: cs_pkcs11_R3.cfg
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.utimaco" -}}
- name: cs-pkcs11-r3-cfg
  configMap:
    name: {{ .Values.hsm.utimaco.hsmConfigurationConfigMap }}
    items:
      - key: "cs_pkcs11_R3.cfg"
        path: "cs_pkcs11_R3.cfg"
{{- end -}}

{{/*
Enable individual sidecars and volumes: Nshield
*/}}
{{- define "ejbca.hsm.sidecar.nshield" -}}
{{- if .Values.hsm.nshield.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  envFrom:
    - secretRef:
        name: nshield-secret
{{- end }}
{{- end -}}

{{/*
Enable individual sidecars and volumes: AWS CloudHSM
*/}}
{{- define "ejbca.hsm.sidecar.awsCloudHsm" -}}
{{- if .Values.hsm.awsCloudHsm.enabled }}
- name: hsm
  image: {{ include "ejbca.hsmImage" . }}
  imagePullPolicy: {{ .Values.hsm.imagePullPolicy }}
  env:
    - name: CLOUDHSM_IP_ADDRESS
      value: {{ .Values.hsm.awsCloudHsm.hsmIpAddress }}
    - name: CLOUDHSM_LOG_LEVEL
      value: {{ .Values.hsm.awsCloudHsm.logLevel }}
  volumeMounts:
    - name: customercacrt
      mountPath: "/opt/configmap/customerCA.crt"
      subPath: "customerCA.crt"
{{- end }}
{{- end -}}

{{- define "ejbca.hsm.volume.awsCloudHsm" -}}
- name: customercacrt
  configMap:
    name: {{ .Values.hsm.awsCloudHsm.customerCACrtConfigMap }}
    items:
      - key: "customerCA.crt"
        path: "customerCA.crt"
{{- end -}}
