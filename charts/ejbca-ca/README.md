# ejbca-ca

Helm chart for deploying EJBCA as a CA. Designed to be simple and flexible.

We are open to contributions and suggestions for new features to add.


# Deployment Scenarios

## Try EJBCA with a temporary instance

Default values will deploy EJBCA as an ephemeral instance with in-memory database that is lost when the instance is stopped.
Administration web access is available to anyone connecting over confidential transport (HTTPS), default NodePort 30443. Non-confidential access is available on NodePort 30080.

Install with:

    helm install [NAME] ejbca/

## Setup EJBCA with data persistence

### Deploy EJBCA with persistent H2 database

ejbca.useH2Persistence: true
ejbca.existingH2PersistenceClaim: "database-data-claim"

### Deploy EJBCA with an external database

ejbca.env.
ejbca.env.DATABASE_JDBC_URL: <database URL>
ejbca.env.DATABASE_USER: <database user name>
ejbca.env.DATABASE_PASSWORD: <database user password>

## Setup EJBCA behind a reverse proxy server

### Deploy EJBCA behind Ingress

Disable the EJBCA direct connection service:

services.directHttp.enabled: false

Enable the proxyAJP or proxyHttp service:

services.proxyAJP.enabled: true
or
services.proxyHttp.enabled: true

Enable Ingress configurations:
ingress.enabled: true

Customize Ingress configurations:
ingress.annotations
ingress.hosts
ingress.tls

### Deploy EJBCA with NGINX sidecar container

Disable the EJBCA direct connection service:
services.directHttp.enabled: false

Enable the proxyHttp service:

services.proxyHttp.enabled: true

Enable the NGINX sidecar deployment:
nginx.enabled: true

Customize NGINX configurations:
nginx.host
nginx.service

## Secure Administration Access

### Enroll super administrator certificate

ejbca.env.TLS_SETUP_ENABLED: "true"

Password used for enrolling the initial super administrator certificate can be set in varaible:
ejbca.superadminPasswordOverride: <password>

If custom password is not set, a randomly generated password will be written in the container log at the end of the deployment.

kubectl log <pod>

If NGINX sidecart is enabled, you must specify logs from the EJBCA init container:

kubectl log <pod> -c ejbca-init

### Deploy with external management CA

kubectl create secret generic managementca-secret --from-file=ca.crt=ManagementCA.pem

ejbca.importExternalCas: true
ejbca.externalCasSecret: managementca-secret

# Parameters

## EJBCA Deployment

| Name                             | Description                                                                                            | Default |
| -------------------------------- | ------------------------------------------------------------------------------------------------------ | ------- |
| useEphemeralH2Database           | If in-memory internal H2 database should be used                                                       | true    |
| ejbca.useH2Persistence           | If internal H2 database with persistence should be used. Requires existingH2PersistenceClaim to be set | false   |
| ejbca.existingH2PersistenceClaim | PersistentVolumeClaim that internal H2 database can use for data persistence                           |         |
| ejbca.importExternalCas          | If CA certificates should be imported into EJBCA as external CAs                                       | false   |
| ejbca.externalCasSecret          | Secret containing CA certificates to import into EJBCA as external CAs                                 |         |
| ejbca.importAppserverKeystore    | If an existing keystore should be used for TLS configurations when reverse proxy is not used           | false   |
| ejbca.appserverKeystoreSecret    | Secret containing keystore for TLS configuration of EJBCA application server                           |         |
| ejbca.importAppserverTruststore  | If an existing truststore should be used for TLS configurations when reverse proxy is not used         | false   |
| ejbca.appserverTruststoreSecret  | Secret containing truststore for TLS configuration of EJBCA application server                         |         |
| ejbca.importEjbcaConfFiles       | If run-time overridable application configuration property files should be applied                     | false   |
| ejbca.ejbcaConfFilesSecret       | Secret containing run-time overridable application configuration property files                        |         |
| ejbca.superadminPasswordOverride | If a custom password should be set for the initial superadmin created at first deployment              |         |
| ejbca.importConfigdumpStaged     | Enteprise edition only                                                                                 | false   |
| ejbca.configdumpStagedSecret     | Enteprise edition only                                                                                 |         |
| ejbca.importConfigdumpInitialize | Enteprise edition only                                                                                 | false   |
| ejbca.configdumpInitializeSecret | Enteprise edition only                                                                                 |         |

## EJBCA Environment variables

| Name                                    | Description                                                                                                                                                                                                                                                             | Default |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| ejbca.env.TLS_SETUP_ENABLED             | "true" generates a ManagementCA and initial superadmin user. "simple" allows anyone with HTTPS access to manage the system with full access. "later" requires TLS configured on reverse proxy in front of EJBCA, and allows anyone access over TLS to begin using EJBCA | simple  |
| ejbca.env.INITIAL_ADMIN                 | Overrides the initial EJBCA SuperAdmin Role member match                                                                                                                                                                                                                |         |
| ejbca.env.DATABASE_JDBC_URL             | JDBC URL to external database                                                                                                                                                                                                                                           |         |
| ejbca.env.DATABASE_USER                 | The username part of the credentials to access the external database                                                                                                                                                                                                    |         |
| ejbca.env.DATABASE_PASSWORD             | The password part of the credentials to access the external database                                                                                                                                                                                                    |         |
| ejbca.env.DATABASE_USER_PRIVILEGED      | The username part of the credentials to access the external database is separate account is used for creating tables and schema changes                                                                                                                                 |         |
| ejbca.env.DATABASE_PASSWORD_PRIVILEGED  | The password part of the credentials to access the external database is separate account is used for creating tables and schema changes                                                                                                                                 |         |
| ejbca.env.SMTP_DESTINATION              | Specify the FQDN or IP Address of the SMTP host for EJBCA to send email notifications                                                                                                                                                                                   |         |
| ejbca.env.SMTP_DESTINATION_PORT         | Specify the port number of the SMTP host for EJBCA to send email notifications to the SMTP_DESTINATION host                                                                                                                                                             |         |
| ejbca.env.SMTP_FROM                     | Specify the from address for emails sent from this EJBCA instance                                                                                                                                                                                                       |         |
| ejbca.env.SMTP_TLS_ENABLED              | Used for Wildfly to connect using TLS to the SMTP server. This only supports public CA certificates                                                                                                                                                                     |         |
| ejbca.env.SMTP_SSL_ENABLED              | Used for Wildfly to connect using SSL to the SMTP server                                                                                                                                                                                                                |         |
| ejbca.env.SMTP_USERNAME                 | The username used when authentication is required for SMTP server                                                                                                                                                                                                       |         |
| ejbca.env.SMTP_PASSWORD                 | The password used to authenticate to the SMTP server                                                                                                                                                                                                                    |         |
| ejbca.env.LOG_LEVEL_APP                 | Application log level                                                                                                                                                                                                                                                   |         |
| ejbca.env.LOG_LEVEL_APP_WS_TRANSACTIONS | Application log level for WS transaction logging                                                                                                                                                                                                                        |         |
| ejbca.env.LOG_LEVEL_SERVER              | Application server log level for main system                                                                                                                                                                                                                            |         |
| ejbca.env.LOG_LEVEL_SERVER_SUBSYSTEMS   | Application server log level for sub-systems                                                                                                                                                                                                                            |         |
| ejbca.env.LOG_STORAGE_LOCATION          | Path in the Container (directory) where the log will be saved, so it can be mounted to a host directory. The mounted location must be a writable directory                                                                                                              |         |
| ejbca.env.LOG_STORAGE_MAX_SIZE_MB       | Maximum total size of log files (in MB) before being discarded during log rotation. Minimum requirement: 2 (MB)                                                                                                                                                         |         |
| ejbca.env.LOG_AUDIT_TO_DB               | Set this value to true if the internal EJBCA audit log is needed                                                                                                                                                                                                        |         |
| ejbca.env.TZ                            | TimeZone to use in the container                                                                                                                                                                                                                                        |         |
| ejbca.env.APPSERVER_DEPLOYMENT_TIMEOUT  | This value controls the deployment timeout in seconds for the application server when starting the application                                                                                                                                                          |         |
| ejbca.env.JAVA_OPTS_CUSTOM              | Allows you to override the default JAVA_OPTS that are set in the standalone.conf                                                                                                                                                                                        |         |
| ejbca.env.ADMINWEB_ACCESS               | Set this value to false if you want to disable access to adminweb from the network                                                                                                                                                                                      |         |
| ejbca.env.OCSP_CHECK_SIGN_CERT_VALIDITY | When no OCSP signing certificate is not configured and the CA keys are used for signing OCSP requests set this variable to false                                                                                                                                        |         |
| ejbca.env.PROXY_AJP_BIND                | Run container with an AJP proxy port :8009 bound to the IP address in this variable, e.g. PROXY_AJP_BIND=0.0.0.0                                                                                                                                                        |         |
| ejbca.env.PROXY_HTTP_BIND               | Run container with two HTTP back-end proxy ports :8081 and :8082 configured bound to the IP address in this variable. Port 8082 will accepts the SSL_CLIENT_CERT HTTP header, e.g. PROXY_HTTP_BIND=0.0.0.0                                                              |         |
| ejbca.env.PKCS11_USE_LEGACY_IMPL        | HIDE?                                                                                                                                                                                                                                                                   |         |
| ejbca.env.OBSERVABLE_BIND               | HIDE?                                                                                                                                                                                                                                                                   |         |
| ejbca.env.METRICS_ENABLED               | HIDE?                                                                                                                                                                                                                                                                   |         |
| ejbca.env.HTTPSERVER_HOSTNAME           | HIDE?                                                                                                                                                                                                                                                                   |         |


| Name                       | Description                                                                                                            | Default            |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------ |
| replicaCount               | Number of EJBCA replicas                                                                                               | 1                  |
| image.repository           | EJBCA image repository                                                                                                 | keyfactor/ejbca-ce |
| image.pullPolicy           | EJBCA image pull policy                                                                                                | IfNotPresent       |
| image.tag                  | Overrides the image tag whose default is the chart appVersion                                                          |                    |
| imagePullSecrets           | EJBCA image pull secrets                                                                                               | []                 |
| nameOverride               | Overrides the chart name                                                                                               | ""                 |
| fullnameOverride           | Fully overrides generated name                                                                                         | ""                 |
| serviceAccount.create      | Specifies whether a service account should be created                                                                  | true               |
| serviceAccount.annotations | Annotations to add to the service account                                                                              | {}                 |
| serviceAccount.name        | The name of the service account to use. If not set and create is true, a name is generated using the fullname template | ""                 |
| podAnnotations             | Additional pod annotations                                                                                             | {}                 |
| podSecurityContext         | Pod security context                                                                                                   | {}                 |
| securityContext            | Container security context                                                                                             | {}                 |

| Name                          | Description                                                                                          | Default   |
| ----------------------------- | ---------------------------------------------------------------------------------------------------- | --------- |
| services.directHttp.enabled   | If service for communcating directly with EJBCA container should be enabled                          | true      |
| services.directHttp.type      | Service type for communcating directly with EJBCA container                                          | NodePort  |
| services.directHttp.httpPort  | HTTP port for communcating directly with EJBCA container                                             | 30080     |
| services.directHttp.httpsPort | HTTPS port for communcating directly with EJBCA container                                            | 30443     |
| services.proxyAJP.enabled     | If service for reverse proxy servers to communicate with EJBCA container over AJP should be enabled  | false     |
| services.proxyAJP.type        | Service type for proxy AJP communication                                                             | ClusterIP |
| services.proxyAJP.bindIP      | IP to bind for proxy AJP communication                                                               | 0.0.0.0   |
| services.proxyAJP.port        | Service port for proxy AJP communication                                                             | 8009      |
| services.proxyHttp.enabled    | If service for reverse proxy servers to communicate with EJBCA container over HTTP should be enabled | false     |
| services.proxyHttp.type       | Service type for proxy HTTP communication                                                            | ClusterIP |
| services.proxyHttp.bindIP     | IP to bind for proxy HTTP communication                                                              | 0.0.0.0   |
| services.proxyHttp.httpPort   | Service port for proxy HTTP communication                                                            | 8081      |
| services.proxyHttp.httpsPort  | Service port for proxy HTTP communication that accepts SSL_CLIENT_CERT header                        | 8082      |

| Name                    | Description                                                            | Default  |
| ----------------------- | ---------------------------------------------------------------------- | -------- |
| nginx.enabled           | If NGINX sidecar container should be deploy as reverse proxy for EJBCA | false    |
| nginx.host              | NGINX reverse proxy server name                                        |          |
| nginx.service.type      | Type of service to create for NGINX reverse proxy                      | NodePort |
| nginx.service.httpPort  | HTTP port to use for NGINX reverse proxy                               | 30080    |
| nginx.service.httpsPort | HTTPS port to use for NGINX reverse proxy                              | 30443    |

| Name                | Description                            | Default           |
| ------------------- | -------------------------------------- | ----------------- |
| ingress.enabled     | If ingress should be created for EJBCA | false             |
| ingress.className   | Ingress class name                     | "nginx"           |
| ingress.annotations | Ingress annotations                    | <see values.yaml> |
| ingress.hosts       | Ingress hosts configurations           | []                |
| ingress.tls         | Ingress TLS configurations             | []                |

| Name                                          | Description                                            | Default |
| --------------------------------------------- | ------------------------------------------------------ | ------- |
| resources                                     | Resource requests and limits                           | {}      |
| autoscaling.enabled                           | If autoscaling should be used                          | false   |
| autoscaling.minReplicas                       | Minimum number of replicas for autoscaling deployment  | 1       |
| autoscaling.maxReplicas                       | Maxmimum number of replicas for autoscaling deployment | 5       |
| autoscaling.targetCPUUtilizationPercentage    | Target CPU utilization for autoscaling deployment      | 80      |
| autoscaling.targetMemoryUtilizationPercentage | Target memory utilization for autoscaling deployment   |         |
| nodeSelector                                  | Node labels for pod assignment                         | {}      |
| tolerations                                   | Tolerations for pod assignment                         | []      |
| affinity                                      | Affinity for pod assignment                            | {}      |

