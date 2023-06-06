![EJBCA](.github/community-ejbca-lite.png)

# Helm Chart for EJBCA Community

Helm chart for deploying EJBCA in Kubernetes. Designed to be simple and flexible.

EJBCA covers all your needs – from certificate management, registration and enrollment to certificate validation.

Welcome to EJBCA – the Open Source Certificate Authority (software). EJBCA is one of the longest running CA software projects, providing time-proven robustness, reliability and flexibitlity. EJBCA is platform independent and can easily be scaled out to match the needs of your PKI requirements, whether you’re setting up a national eID, securing your industrial IoT platform or managing your own internal PKI for Enterprise or DevOps.

EJBCA is developed in Java and runs on a JVM such as OpenJDK, available on most platforms such as Linux and Windows.

There are two versions of EJBCA:
* **EJBCA Community** (EJBCA CE) - free and open source, OSI Certified Open Source Software
* **EJBCA Enterprise** (EJBCA EE) - commercial and Common Criteria certified

OSI Certified is a certification mark of the Open Source Initiative.

## Community Support

In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab.
* If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
* Ask the community for ideas: **[EJBCA Discussions](https://github.com/Keyfactor/ejbca-ce/discussions)**.
* Read more in our documentation: **[EJBCA Documentation](https://doc.primekey.com/ejbca)**.
* See release information: **[EJBCA Release information](https://doc.primekey.com/ejbca/ejbca-release-information)**.
* Read more on the open source project website: **[EJBCA website](https://www.ejbca.org/)**.

## Commercial Support
Commercial support is available for **[EJBCA Enterprise](https://www.keyfactor.com/platform/keyfactor-ejbca-enterprise/)**.

## Prerequisites

- [Kubernetes](http://kubernetes.io) v1.19+
- [Helm](https://helm.sh) v3+

## Getting started

The **EJBCA Community Helm Chart** boostraps **EJBCA Community** on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

### Add repo
```shell
helm repo add ejbca-community-helm https://github.com/Keyfactor/ejbca-community-helm
```

### Quick start
```shell
helm install ejbca https://github.com/Keyfactor/ejbca-community-helm --namespace ejbca --create-namespace
```
This command deploys `ejbca-community-helm` on the Kubernetes cluster in the default configuration.

### Custom deployment

To customize the installation, create and edit a custom values file with deployment parameters:
```shell
helm show values https://github.com/Keyfactor/ejbca-community-helm > ejbca.yaml
```
Deploy `ejbca-community-helm` on the Kubernetes cluster with custom configurations:
```shell
helm install ejbca https://github.com/Keyfactor/ejbca-community-helm --namespace ejbca --create-namespace --values ejbca.yaml
```

## Parameters

### EJBCA Deployment Parameters

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
| ejbca.env                        | Environment variables to pass to container                                                             |         |
| ejbca.envRaw                     | Environment variables to pass to container in Kubernetes YAML format                                   |         |

### EJBCA Environment Variables

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

### Services Parameters

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

### NGINX Reverse Proxy Parameters

| Name                    | Description                                                            | Default  |
| ----------------------- | ---------------------------------------------------------------------- | -------- |
| nginx.enabled           | If NGINX sidecar container should be deploy as reverse proxy for EJBCA | false    |
| nginx.host              | NGINX reverse proxy server name                                        |          |
| nginx.service.type      | Type of service to create for NGINX reverse proxy                      | NodePort |
| nginx.service.httpPort  | HTTP port to use for NGINX reverse proxy                               | 30080    |
| nginx.service.httpsPort | HTTPS port to use for NGINX reverse proxy                              | 30443    |

### Ingress Parameters

| Name                | Description                            | Default           |
| ------------------- | -------------------------------------- | ----------------- |
| ingress.enabled     | If ingress should be created for EJBCA | false             |
| ingress.className   | Ingress class name                     | "nginx"           |
| ingress.annotations | Ingress annotations                    | <see values.yaml> |
| ingress.hosts       | Ingress hosts configurations           | []                |
| ingress.tls         | Ingress TLS configurations             | []                |

### Deployment Parameters

| Name                                          | Description                                                                                                            | Default            |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------ |
| replicaCount                                  | Number of EJBCA replicas                                                                                               | 1                  |
| image.repository                              | EJBCA image repository                                                                                                 | keyfactor/ejbca-ce |
| image.pullPolicy                              | EJBCA image pull policy                                                                                                | IfNotPresent       |
| image.tag                                     | Overrides the image tag whose default is the chart appVersion                                                          |                    |
| imagePullSecrets                              | EJBCA image pull secrets                                                                                               | []                 |
| nameOverride                                  | Overrides the chart name                                                                                               | ""                 |
| fullnameOverride                              | Fully overrides generated name                                                                                         | ""                 |
| serviceAccount.create                         | Specifies whether a service account should be created                                                                  | true               |
| serviceAccount.annotations                    | Annotations to add to the service account                                                                              | {}                 |
| serviceAccount.name                           | The name of the service account to use. If not set and create is true, a name is generated using the fullname template | ""                 |
| podAnnotations                                | Additional pod annotations                                                                                             | {}                 |
| podSecurityContext                            | Pod security context                                                                                                   | {}                 |
| securityContext                               | Container security context                                                                                             | {}                 |
| resources                                     | Resource requests and limits                                                                                           | {}                 |
| autoscaling.enabled                           | If autoscaling should be used                                                                                          | false              |
| autoscaling.minReplicas                       | Minimum number of replicas for autoscaling deployment                                                                  | 1                  |
| autoscaling.maxReplicas                       | Maxmimum number of replicas for autoscaling deployment                                                                 | 5                  |
| autoscaling.targetCPUUtilizationPercentage    | Target CPU utilization for autoscaling deployment                                                                      | 80                 |
| autoscaling.targetMemoryUtilizationPercentage | Target memory utilization for autoscaling deployment                                                                   |                    |
| nodeSelector                                  | Node labels for pod assignment                                                                                         | {}                 |
| tolerations                                   | Tolerations for pod assignment                                                                                         | []                 |
| affinity                                      | Affinity for pod assignment                                                                                            | {}                 |

## Community Support

In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab.
* If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
* Ask the community for ideas: **[EJBCA Discussions](https://github.com/Keyfactor/ejbca-ce/discussions)**.
* Read more in our documentation: **[EJBCA Documentation](https://doc.primekey.com/ejbca)**.
* See release information: **[EJBCA Release information](https://doc.primekey.com/ejbca/ejbca-release-information)**.
* Read more on the open source project website: **[EJBCA website](https://www.ejbca.org/)**.

## Commercial Support
Commercial support is available for **[EJBCA Enterprise](https://www.keyfactor.com/platform/keyfactor-ejbca-enterprise/)**.
