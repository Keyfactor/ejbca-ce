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

## License
EJBCA Community is licensed under the LGPL license, please see **[LICENSE](LICENSE)**.


## Prerequisites

- [Kubernetes](http://kubernetes.io) v1.19+
- [Helm](https://helm.sh) v3+

## Getting started

The **EJBCA Community Helm Chart** boostraps **EJBCA Community** on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

### Add repo
```shell
helm repo add keyfactor https://keyfactor.github.io/ejbca-community-helm/
```

### Quick start
```shell
helm install ejbca keyfactor/ejbca-community-helm --namespace ejbca --create-namespace
```
This command deploys `ejbca-community-helm` on the Kubernetes cluster in the default configuration.

### Custom deployment

To customize the installation, create and edit a custom values file with deployment parameters:
```shell
helm show values keyfactor/ejbca-community-helm > ejbca.yaml
```
Deploy `ejbca-community-helm` on the Kubernetes cluster with custom configurations:
```shell
helm install ejbca keyfactor/ejbca-community-helm --namespace ejbca --create-namespace --values ejbca.yaml
```

## Example Custom Deployments

This section contains examples for how to customize the deployment for common scenarios.

### Connecting EJBCA to an external database

All serious deployments of EJBCA should use an external database for data persistence.
EJBCA supports Microsoft SQL Server, MariaDB/MySQL, PostgreSQL and Oracle databases. 

The following example shows modifications to the helm chart values file used to connect EJBCA to a MariaDB database with server name `mariadb-server` and database name `ejbcadb` using username `ejbca` and password `foo123`:

```yaml
ejbca:
  useEphemeralH2Database: false
  env:
    DATABASE_JDBC_URL: jdbc:mariadb://mariadb-server:3306/ejbcadb?characterEncoding=UTF-8
    DATABASE_USER: ejbca
    DATABASE_PASSWORD: foo123
```

This example connects EJBCA to an PostgreSQL database and uses a Kubernetes secret for storing the database username and password:

```yaml
ejbca:
  useEphemeralH2Database: false
  env:
    DATABASE_JDBC_URL: jdbc:postgresql://postgresql-server:5432/ejbcadb
  envRaw:
    - name: DATABASE_PASSWORD
      valueFrom:
       secretKeyRef:
         name: ejbca-db-credentials
         key: database_password
    - name: DATABASE_USER
      valueFrom:
       secretKeyRef:
         name: ejbca-db-credentials
         key: database_user
```

Helm charts can be used to deploy a database in Kubernetes, for example the following by Bitnami:

- https://artifacthub.io/packages/helm/bitnami/postgresql
- https://artifacthub.io/packages/helm/bitnami/mariadb

### Connecting EJBCA to SMTP server for sending notifications

The following exmaple shows variables that need to be set in order to prepare a deployment for send e-mail notifications:

```yaml
ejbca:
  env:
    SMTP_DESTINATION: smtp-server
    SMTP_PORT: 25
    SMTP_FROM: noreply@ejbca.org
    SMTP_TLS_ENABLED: false
    SMTP_SSL_ENABLED: false
```

For information on how to configure EJBCA for sending notifications, see https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/end-entities-overview/end-entity-profiles-overview/e-mail-notifications

### Deploying a reverse proxy server in front of EJBCA

It is best practise to place EJBCA behind a reverse proxy server that handles TLS termination and/or load balancing.

The following example shows how to configure a deployment to expose an AJP proxy port as a ClusterIP service:

```yaml
services:
  directHttp:
    enabled: false
  proxyAJP:
    enabled: true
    type: ClusterIP
    bindIP: 0.0.0.0
    port: 8009
  proxyHttp:
    enabled: false
```

This example exposes two proxy HTTP ports, where port 8082 will accept the SSL_CLIENT_CERT HTTP header to enable mTLS:

```yaml
services:
  directHttp:
    enabled: false
  proxyAJP:
    enabled: false
  proxyHttp:
    enabled: true
    type: ClusterIP
    bindIP: 0.0.0.0
    httpPort: 8081
    httpsPort: 8082
```

This helm chart can deploy Nginx as a reverse proxy in front of EJBCA and expose it as a service. A local EJBCA management CA will be used to issue TLS certificate for the DNS name specified in `nginx.host`. The Nginx server can be configured in the variable `nginx.conf`.

```yaml
nginx:
  enabled: true
  host: "ejbca.minikube.local"
  service:
    type: NodePort
    httpPort: 30080
    httpsPort: 30443
  conf: |
    <nginx configurations>
```

### Enabling Ingress in front of EJBCA

Ingress is a Kubernetes native way of exposing HTTP and HTTPS routes from outside to Kubernetes services.

The following example shows how Ingress can be enabled with this helm chart using proxy AJP. Note that a TLS secret containing `tls.crt` and `tls.key` with certificate and private key would need to be prepared in advance.


```yaml
services:
  directHttp:
    enabled: false
  proxyAJP:
    enabled: true
    type: ClusterIP
    bindIP: 0.0.0.0
    port: 8009
  proxyHttp:
    enabled: false

ingress:
  enabled: true
  className: "nginx"
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false"
    nginx.ingress.kubernetes.io/auth-tls-verify-client: "optional_no_ca"
    nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream: "true"
  hosts:
    - host: "ejbca.minikube.local"
      paths:
        - path: /ejbca
          pathType: Prefix
  tls:
    - hosts:
        - ejbca.minikube.local
      secretName: ingress-tls
```

### Using init containers and sidecar containers

The init containers and sidecar containers can be used to customize the deployment (for example, if you need to run security module service as additional container, or do some extra validation before EJBCA startup). The following example shows how to use sidecar containers (init containers are configured the same way):

```yaml
ejbca:
  sidecarContainers:
    - name: hsm
      image: hsm-image
      imagePullPolicy: IfNotPresent
      volumeMounts:
        - name: config
          mountPath: /opt/config
          readOnly: true
        - name: socket
          mountPath: /opt/sockets
```

Additionally, sidecar containers can expose ports. The following example shows how to expose port to the sidecar container to in EJBCA deployment:

```yaml
service:
  sidecarPorts:
    - name: hsm-port
      port: 1234
      targetPort: 1234 
```

### Using additional volumes and volume mounts

Additional volumes and volume mounts can be used to customize the deployment (for example, if you need to mount a volume with a custom configuration file, sockets, etc.). The following example shows how to use additional volumes and volume mounts:

```yaml
ejbca:
  volumes:
    - name: socket
      emptyDir: {}
  volumeMounts:
    - name: socket
      mountPath: /opt/sockets
```

## Parameters

### EJBCA Deployment Parameters

| Name                             | Description                                                                                                                            | Default |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| ejbca.useEphemeralH2Database           | If in-memory internal H2 database should be used                                                                                       | true    |
| ejbca.useH2Persistence           | If internal H2 database with persistence should be used. Requires existingH2PersistenceClaim to be set                                 | false   |
| ejbca.existingH2PersistenceClaim | PersistentVolumeClaim that internal H2 database can use for data persistence                                                           |         |
| ejbca.importExternalCas          | If CA certificates should be imported into EJBCA as external CAs                                                                       | false   |
| ejbca.externalCasSecret          | Secret containing CA certificates to import into EJBCA as external CAs                                                                 |         |
| ejbca.importAppserverKeystore    | If an existing keystore should be used for TLS configurations when reverse proxy is not used                                           | false   |
| ejbca.appserverKeystoreSecret    | Secret containing keystore for TLS configuration of EJBCA application server                                                           |         |
| ejbca.importAppserverTruststore  | If an existing truststore should be used for TLS configurations when reverse proxy is not used                                         | false   |
| ejbca.appserverTruststoreSecret  | Secret containing truststore for TLS configuration of EJBCA application server                                                         |         |
| ejbca.importEjbcaConfFiles       | If run-time overridable application configuration property files should be applied                                                     | false   |
| ejbca.ejbcaConfFilesSecret       | Secret containing run-time overridable application configuration property files                                                        |         |
| ejbca.superadminPasswordOverride | If a custom password should be set for the initial superadmin created at first deployment. Requires ejbca.env.TLS_SETUP_ENABLED "true" |         |
| ejbca.env                        | Environment variables to pass to container                                                                                             |         |
| ejbca.envRaw                     | Environment variables to pass to container in Kubernetes YAML format                                                                   |         |
| ejbca.initContainers             | Extra init containers to be added to the deployment                                                                                    | []      |
| ejbca.sidecarContainers          | Extra sidecar containers to be added to the deployment                                                                                 | []      |
| ejbca.volumes                    | Extra volumes to be added to the deployment                                                                                            | []      |
| ejbca.volumeMounts               | Extra volume mounts to be added to the deployment                                                                                      | []      |

### EJBCA Environment Variables

Environment variables can be used to change many options that are not runtime configurable in EJBCA and the application server. 
Use ejbca.env.VAR, i.e. ejbca.env.PROXY_AJP_BIND, to set a specific environment variable in the Helm chart.

**Proxy back-end settings**

Configuring the container as a proxy back-end will disable legacy installation workflow or any local TLS server side certificate generation. The Admin UI will be open to anyone will network access until configured otherwise.

Running the container behind a front-end proxy (like Nginx or Apache Httpd) that terminates TLS connections is currently the expected setup for any kind of production-like deployment.

When binding a proxy back-end protocol port to
* an IP that can later be exposed outside the container (e.g. "0.0.0.0") care needs to be taken to ensure that no traffic can reach the bound port directly.
* a local IP (e.g. "127.0.0.1") it is expected that a side-car deployment in the same Pod will be used and forward requests inside the Pod.

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
| PROXY_AJP_BIND     |Run container with an AJP proxy port :8009 bound to the IP address in this variable, e.g. PROXY_AJP_BIND=0.0.0.0||
| PROXY_HTTP_BIND     |Run container with two HTTP back-end proxy ports :8081 and :8082 configured bound to the IP address in this variable. Port 8082 will accepts the SSL_CLIENT_CERT HTTP header, e.g. PROXY_HTTP_BIND=0.0.0.0||
| TLS_SETUP_ENABLED     | **true** - the container will generate a ManagementCA that will be used to issue both server and initial client TLS certificate used for administration. **simple** - no client TLS certificate will be used initially and anyone with HTTPS access will be able to manage the instance with full access. **false** - this will disable container internal TLS setup and anyone with HTTP access will be able to manage the instance with full access. Currently EJBCA's Admin GUI is not very functional in this setup, since it was designed for secure use. **later** - requires TLS configured on reverse proxy in front of EJBCA, and allows anyone access over TLS to begin using EJBCA|simple|
| INITIAL_ADMIN |Overrides the initial EJBCA SuperAdmin Role member match. During the classic installation workflow, this is set to  "ManagementCA;CertificateAuthenticationToken:WITH_COMMONNAME;SuperAdmin". When an external ManagementCA is imported using "-v /hostpath/SomeCA.der:/mnt/secrets/tls/cas/ManagementCA.crt" or using a ConfigMap in proxy mode, this is required to enable initial client certificate authentication. By default the *.crt file must be mounted to /opt/keyfactor/secrets/tls/cas/. When mounting a <>.crt, <> becomes the name of the ManagementCA in EJBCA. Example INITIAL_ADMIN string(s) when mounting the *.crt to add roles: ManagementCA;WITH_COMMONNAME;SuperAdmin. Setting this to ";PublicAccessAuthenticationToken:TRANSPORT_ANY;" will start EJBCA as a completely open system.|<empty>|
| HTTPSERVER_HOSTNAME | Hostname of this instance's front end access point to use when configuring OAuth. The name asserted in the variable would be used on the OAuth side after authentication to pass back after successful authentication. If the name in this variable does not match what is configured on the OAuth side authentication will fail.|The hostname of the container instance |

**Standalone container**

We strongly encourage customers to use EJBCA container with a front-end proxy like Nginx or Apache Httpd as described in last section. But it is also possible to use EJBCA container without a proxy. This is mainly relevant when using Microsoft App Server. One can also run the EJBCA container on any host and setup proper port forwarding to have a simpler setup.
The environment variables described in previous section are also applicable for standalone setup except PROXY_AJP_BIND and PROXY_HTTP_BIND.
Generally server TLS credentials to be volume mounted to an EJBCA container as described in Directories of importance . If they are absent,  EJBCA container tries to create server TLS credentials/keystore automatically during starting up for the first time. EJBCA uses ManagementCA to create this keystore. This TLS credential should be persisted using a volume for later use. 
This feature allows a quicker setup of a cluster with CA nodes.  Normally CA nodes connect to a replicated database and HSMs with same key material. Cluster administrator does not need to create credentials for each node.

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
| APPSERVER_KEYSTORE_SECRET |Administrator may specify the password for the server TLS keystore using this. If not mentioned an randomly generated string will be used. ||
| APPSERVER_TRUSTSTORE_SECRET |Similarly for the password for the truststore.||

**Database configuration**

The application stores all run-time configuration and state in a SQL database (with the Exception of key material when an Hardware Security Module is used). In clustered setup all nodes need to share the same view of the applications database.

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
| DATABASE_JDBC_URL | Java Database Connectivity API is used by the application to communicate with the SQL database. Based on the specified URL, the application will know how and where to store the data. By default the container will use an in-memory H2 database that is persisted between runs if the container is stopped gracefully which is useful for single node non-production testing, but not much else. The JDBC drivers for MariaDB/MySQL, Microsoft SQL Server, and PostgreSQL are bundled with the container to work out of the box by specifying the corresponding JDBC URL. We recommend the use of MariaDB with Galera clustering for production setups.|jdbc:h2:/mnt/persistent/ejbcadb;DB_CLOSE_DELAY=-1 |
| DATABASE_USER |The username part of the credentials to access the external database. Not required for use of the H2 database.| ejbca |
| DATABASE_PASSWORD |The password part of the credentials to access the external database. Not required for use of the H2 database.| ejbca | 
| DATABASE_USER_PRIVILEGED |The privileged username part of the credentials to access the external database for table creation or altering. Only needed for initial container startup to create tables or upgrading EJBCA when database schema has changes. Not required for use of the H2 database.||
| DATABASE_PASSWORD_PRIVILEGED |The privileged password part of the credentials to access the external database for table creation or altering. Only needed for initial container startup to create tables or upgrading EJBCA when database schema has changes. Not required for use of the H2 database.||

**Security keys**

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
|PASSWORD_ENCRYPTION_KEY|The following key (strictly speaking, PBE input password) allows for encrypting passwords used in EJBCA (e.g. End Entity, Crypto Token, CMP Alias, SCEP Alias, etc, passwords stored in database). This property should be set before initial EJBCA installation and it shouldn't be changed later, because there could exist passwords encrypted with the key about to be changed and EJBCA would be unable to decrypt them (note that the current implementation is capable to try decryption with the default key, i.e. qhrnf.f8743;12%#75, but it won't be able to decrypt passwords encrypted with a custom key being replaced for another custom key). For setting this property you could use any password you consider safe, but it is strongly recommended that you use a randomly generated password, e.g. by using `openssl rand -base64 24`.When upgrading a 100% up-time cluster all nodes must produce password encryption that is decryptable by old nodes. When all nodes run EJBCA 6.8.0 or higher you can change the password, and count, to increase security when passwords are saved in clear text (mostly used for batch generation and auto-activation). ||
|CA_KEYSTOREPASS|This password is used internally to protect CA keystores in database unless a password has been set manually. CA keystores are the CAs private key, where a password can be defined manually instead when creating the Crypto Token, and Extended CA Services, such as the 'CMS Service', where a manual password can not be defined. The default value foo123 is needed to keep compatibility with default installations of EJBCA 3.0. Please change if possible. This value is not very important if you define your own Crypto Token Authentication Codes, which is recommended or you don't use the CMS Service (which most do not). |foo123|
|EJBCA_CLI_DEFAULTPASSWORD|Password used for the EJBCA CLI. Using a custom password requires the password to then be provided when using the CLI.||

**Email**

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
|SMTP_DESTINATION| Specify the FQDN or IP Address of the SMTP host for EJBCA to send email notifications. |localhost|
|SMTP_DESTINATION_PORT|Specify the port number of the SMTP host for EJBCA to send email notifications to the SMTP_DESTINATION host.|25|
|SMTP_FROM|Specify the from address for emails sent from this EJBCA instance.|no-reply@localhost|
|SMTP_TLS_ENABLED|Used for Wildfly to connect using TLS to the SMTP server. This only supports public CA certificates.|true|
|SMTP_SSL_ENABLED|Used for Wildfly to connect using SSL to the SMTP server.|true|
|SMTP_USERNAME|The username used when authentication is required for SMTP server.|ejbca-mail|
|SMTP_PASSWORD|The password used to authenticate to the SMTP server.|ejbca|

**Observability**

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
|OBSERVABLE_BIND|The IP address where port 8090 will listen for requests to /health, /health/ready, /health/live and /metrics . Set this to 0.0.0.0 to bind to all container interfaces.|127.0.0.1|
|METRICS_ENABLED|Set this to "true" to collect metrics and expose them at the /metrics endpoint for scraping.|false|

**Logging**

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
|LOG_LEVEL_APP|Application log level.|INFO|
|LOG_LEVEL_APP_WS_TRANSACTIONS|Application log level for WS transaction logging. These log entries are always logged at DEBUG log level. Set this log level to DEBUG or lower to enable and INFO or higher to disable.|DEBUG (enabled)|
|LOG_LEVEL_SERVER|Application server log level for main system.|INFO|
|LOG_LEVEL_SERVER_SUBSYSTEMS|Application server log level for sub-systems.|WARN|
|LOG_STORAGE_LOCATION|String: Path in the Container (directory) where the log will be saved, so it can be mounted to a host directory. The mounted location must be a writable directory. Non-writable directory will cause the Container to fail the startup.|Disabled (empty)|
|LOG_STORAGE_MAX_SIZE_MB|Integer: Maximum total size of log files (in MB) before being discarded during log rotation. Minimum requirement: 2 (MB)|256 (MB)|
|LOG_AUDIT_TO_DB|Set this value to true (LOG_AUDIT_TO_DB=true) if the internal EJBCA audit log is needed.   Common use of these systems will have a proper logging system in place (which is possibly better than what EJBCA provides) therefore this value is set to false by default (or if unspecified).|false|

**Miscellaneous**

The following lists other variables that provide additional miscellaneous capabilities to the container.

| Vaiable   | Description | Default |
| :--------- | :------------|:------------|
|TZ|TimeZone to use in the container. Since the system TimeZone is used both for logging and currently also for presentation in the UI this improves usability.|UTC|
|APPSERVER_DEPLOYMENT_TIMEOUT|This value controls the deployment timeout in seconds for the application server when starting the application. If EJBCA fails to perform early start-up tasks like eager loading of CAs due to the application server timing out, you can adjust this setting. Normally this could also indicate that the resources assigned to the database are insufficient compared to the scale of the PKI.|300|
|PKCS11_USE_LEGACY_IMPL|Force EJBCA EE 7.6.0+ to use the legacy Sun PKCS#11 Provider from the JRE (SunPKCS11 in module jdk.crypt.cryptoki) instead of the P11NG implementation maintained by Keyfactor by setting this to "true". This is not recommended for new installations.|unset|
|JAVA_OPTS_CUSTOM|Allows you to override the default JAVA_OPTS that are set in the standalone.conf. The default settings will calculate memory automatically. If you specify any one of the options that can be set in standalone.conf, you will set only that value removing the defaults. For example, to set the value for -XX:MaxMetaspaceSize=512m (default is 256), set all values like this: name: JAVA_OPTS_CUSTOM value: -Xms128m -Xmx1558m -Xss256k -XX:MetaspaceSize=160m -XX:MaxMetaspaceSize=512m||
|ADMINWEB_ACCESS|Set this value to false if you want to disable access to adminweb from the network. Access is only possible if accessing from localhost (127.0.0.1).|true|
|OCSP_CHECK_SIGN_CERT_VALIDITY|When no OCSP signing certificate is not configured and the CA keys are used for signing OCSP requests set this variable to false. If OCSP signing certificates are used then leave this value as the default true.|true|
|OCSP_NON_EXISTING_IS_GOOD|Respond with 'good' when receiving OCSP requests for non-existing certificates|false|
|OCSP_SIGNATUREALGORITHM|Override with custom algorithms specified in variable|SHA256WithRSA; SHA256withRSAandMGF1; SHA384WithRSA; SHA512WithRSA; SHA224withECDSA; SHA256withECDSA; SHA384withECDSA; SHA512withECDSA; SHA1WithDSA; Ed25519; Ed448|

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
| services.sidecarPorts         | Additional ports to expose in sidecar containers                                                     | []        |

### NGINX Reverse Proxy Parameters

| Name                    | Description                                                            | Default  |
| ----------------------- | ---------------------------------------------------------------------- | -------- |
| nginx.enabled           | If NGINX sidecar container should be deploy as reverse proxy for EJBCA | false    |
| nginx.host              | NGINX reverse proxy server name                                        |          |
| nginx.service.type      | Type of service to create for NGINX reverse proxy                      | NodePort |
| nginx.service.httpPort  | HTTP port to use for NGINX reverse proxy                               | 30080    |
| nginx.service.httpsPort | HTTPS port to use for NGINX reverse proxy                              | 30443    |
| nginx.conf              | NGINX server configuration parameters                                  |          |

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
