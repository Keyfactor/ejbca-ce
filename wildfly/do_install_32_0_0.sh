#!/bin/bash

export zipfile="wildfly-${version}.zip"
show "# Downloading Wildfly32"

run_cmd "rm -rf /tmp/${zipfile}"
run_cmd "wget https://github.com/wildfly/wildfly/releases/download/${version}/${zipfile} -O /tmp/${zipfile}"

show "# Unpacking Wildfly32 into ${install_dir}"
run_cmd "sudo rm -rf ${install_dir}/wildfly"
run_cmd "sudo rm -rf ${install_dir}/wildfly-${version}"
run_cmd "sudo unzip -q /tmp/${zipfile} -d ${install_dir}/"
run_cmd "sudo ln -snf ${install_dir}/wildfly-${version} ${install_dir}/wildfly"
run_cmd "sudo rm -rf /tmp/${zipfile}"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly-${version}"

show "# Remove RESTEasy-Crypto"
run_cmd "sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' ${wildfly_dir}/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml"
run_cmd "rm -rf ${wildfly_dir}/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/"

show "# Create a Custom Configuration"
run_cmd "cp standalone.conf ${wildfly_dir}/bin/"
run_cmd "sed -i -e 's/{{ HEAP_SIZE }}/2048/g' ${wildfly_dir}/bin/standalone.conf"
export random_string=$(od -A n -t d -N 1 /dev/urandom | tr -d ' ')
run_cmd "sed -i -e \"s/{{ TX_NODE_ID }}/$random_string/g\" ${wildfly_dir}/bin/standalone.conf"

show "# Start WildFly"
show "$ ${wildfly_dir}/bin/standalone.sh 2>&1 1>wildfly-$version.log &"
# Warning! Don't make any function-call to 'run_cmd' with command ending with '&'
export current_dir=$(pwd)
pushd ${wildfly_dir}/bin/
./standalone.sh 2>&1 1>$current_dir/wildfly-$version.log &
popd
run_cmd "sleep 5"
export wildfly_pid=$(sudo lsof -i :9990|sed 's/java\s*//g'|sed 's/\s.*//g'|grep -iv command)
echo "PID=$wildfly_pid"

show "# Create an Elytron Credential Store"

show "# Create a Master Password"
run_cmd "rm -rf wildfly_pass_$version"
run_cmd "echo '#!/bin/sh' > wildfly_pass_$version"
run_cmd "echo \"echo '$(openssl rand -base64 24)'\" >> wildfly_pass_$version"
run_cmd "sudo rm -rf /usr/bin/wildfly_pass_$version"
run_cmd "sudo mv wildfly_pass_$version /usr/bin/"
run_cmd "sudo chown $wildflyuser:$wildflyuser /usr/bin/wildfly_pass_$version"
run_cmd "sudo chmod 700 /usr/bin/wildfly_pass_$version"

# This is a bug in WildFly. https://stackoverflow.com/questions/28254956/duplicate-resource-wildfly
set +e
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add(path=keystore/credentials, relative-to=jboss.server.config.dir, credential-reference={clear-text=\"{EXT}/usr/bin/wildfly_pass_$version\", type=\"COMMAND\"}, create=true)'"

show "# Configure WildFly Remoting"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)'"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)'"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)'"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect ':reload'"

show "# Configure logging"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.ejbca:add(level=INFO)'"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.cesecore:add(level=INFO)'"
run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=logging/logger=com.keyfactor:add(level=INFO)'"

show "# Add Access Logging"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/host=default-host/setting=access-log:add(pattern=\"%h %t \\\"%r\\\" %s \\\"%{i,User-Agent}\\\"\", relative-to=jboss.server.log.dir, directory=access-logs)'"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=io.undertow.accesslog:add(level=INFO)'"

set -e

# echo "* Configure firewall"
# sudo ufw enable
# systemctl enable firewalld --now
# firewall-cmd --set-default-zone=dmz
# firewall-cmd --zone=dmz --permanent --add-port 8080/tcp
# firewall-cmd --zone=dmz --permanent --add-port 8443/tcp
# firewall-cmd --reload

show "# Make sure it is possible to copy new files into deployments folder"
run_cmd "sudo chmod 777 ${wildfly_dir}/standalone/deployments"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly-${version}"

# Warning!
# It is important to first download the driver completely to a folder outside of the the Wildfly deployment folder
# and then copy it into the WildFly deployment folder. Otherwise WildFly will try to extract it before the jar-file
# is downloaded and thereby think it is empty.

case $db in
  mariadb)
    show "# Downloading driver for MariaDB"
    
    run_cmd "wget https://dlm.mariadb.com/3852266/Connectors/java/connector-java-3.4.1/mariadb-java-client-3.4.1.jar -O mariadb-java-client.jar"
    run_cmd "mv mariadb-java-client.jar ${wildfly_dir}/standalone/deployments/"
    sleep 5s # Wait until it is deployed

    show "# Adding datasource"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect 'data-source add --name=ejbcads --connection-url=\"jdbc:mysql://127.0.0.1:3306/ejbca?permitMysqlScheme\" --jndi-name=\"java:/EjbcaDS\" --use-ccm=true --driver-name=\"mariadb-java-client.jar\" --driver-class=\"org.mariadb.jdbc.Driver\" --user-name=\"ejbca\" --credential-reference={store=defaultCS, alias=dbPassword} --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql=\"select 1;\"'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect ':reload'"
    ;;
  postgres)
    show "# Downloading driver for PostgreSQL"
    run_cmd "wget https://jdbc.postgresql.org/download/postgresql-42.2.18.jar -O postgresql-jdbc4.jar"
    run_cmd "mv postgresql-jdbc4.jar ${wildfly_dir}/standalone/deployments/"
    sleep 5s # Wait until it is deployed

    show "# Adding datasource"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect 'data-source add --name=ejbcads --connection-url=\"jdbc:postgresql://127.0.0.1/ejbca\" --jndi-name=\"java:/EjbcaDS\" --use-ccm=true --driver-name=\"postgresql.jar\" --driver-class=\"org.postgresql.Driver\" --user-name=\"ejbca\" --credential-reference={store=defaultCS, alias=dbPassword} --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql=\"select 1;\"'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect ':reload'"
    ;;
  mssql)
    show "# Downloading driver for MSSQL"
    run_cmd "wget https://github.com/microsoft/mssql-jdbc/releases/download/v12.8.1/mssql-jdbc-12.8.1.jre11.jar -O mssql-jdbc.jre11.jar"
    run_cmd "mv mssql-jdbc.jre11.jar ${wildfly_dir}/standalone/deployments/"
    sleep 5s # Wait until it is deployed

    show "# Adding datasource"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect '/subsystem=datasources/data-source=ejbcads:add(connection-url=\"jdbc:sqlserver://foobar.YOUR.DOMAIN:1433;DatabaseName=ejbca;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;sendStringParametersAsUnicode=false\", min-pool-size=5, max-pool-size=150, jndi-name=\"java:/EjbcaDS\", driver-name=mssql-jdbc.jre11.jar, user-name=\"ejbca\", credential-reference={store=defaultCS, alias=dbPassword}, pool-prefill=false, pool-use-strict-min=false, idle-timeout-minutes=2)'"
    run_cmd "${wildfly_dir}/bin/jboss-cli.sh --connect ':reload'"
    ;;
  *)
    show "${db} is an unknown database. Valid options are: mariadb, postgres and mssql."
    run_cmd "exit 1"
    ;;
esac

show "# Remove Existing TLS and HTTP Configuration"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=default:remove()'"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=http:remove()'"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=https:remove()'"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=https:remove()'"
run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"

if [ "${port_separation}" = "3" ];
then
  show "# Using 3 port separation"
  show "# Add New Interfaces and Sockets"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/interface=http:add(inet-address=\"0.0.0.0\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/interface=httpspub:add(inet-address=\"0.0.0.0\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/interface=httpspriv:add(inet-address=\"0.0.0.0\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=http:add(port=\"8080\",interface=\"http\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=httpspub:add(port=\"8442\",interface=\"httpspub\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=httpspriv:add(port=\"8443\",interface=\"httpspriv\")'"

  show "# Configure TLS"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsKeystorePassword, secret-value=\"serverpwd\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsTruststorePassword, secret-value=\"changeit\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsKS:add(path=\"keystore/keystore.p12\",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsKeystorePassword},type=PKCS12)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsTS:add(path=\"keystore/truststore.p12\",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsTruststorePassword},type=PKCS12)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm=\"SunX509\",credential-reference={store=defaultCS, alias=httpsKeystorePassword})'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/server-ssl-context=httpspub:add(key-manager=httpsKM,protocols=[\"TLSv1.3\",\"TLSv1.2\"],use-cipher-suites-order=false,cipher-suite-filter=\"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\",cipher-suite-names=\"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/server-ssl-context=httpspriv:add(key-manager=httpsKM,protocols=[\"TLSv1.3\",\"TLSv1.2\"],use-cipher-suites-order=false,cipher-suite-filter=\"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\",cipher-suite-names=\"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256\",trust-manager=httpsTM,need-client-auth=true)'"

  show "# Add HTTP(S) listeners"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding=\"http\", redirect-socket=\"httpspriv\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=httpspub:add(socket-binding=\"httpspub\", ssl-context=\"httpspub\", max-parameters=2048)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding=\"httpspriv\", ssl-context=\"httpspriv\", max-parameters=2048)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"
fi

if [ "${port_separation}" = "2" ];
then
  show "# Using 2 port separation"
  show "# Add New Interfaces and Sockets"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/interface=http:add(inet-address=\"0.0.0.0\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/interface=https:add(inet-address=\"0.0.0.0\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=http:add(port=\"8080\",interface=\"http\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=https:add(port=\"8443\",interface=\"https\")'"

  show "# Configure TLS"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsKeystorePassword, secret-value=\"serverpwd\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsTruststorePassword, secret-value=\"changeit\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsKS:add(path=\"keystore/keystore.p12\",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsKeystorePassword},type=PKCS12)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsTS:add(path=\"keystore/truststore.p12\",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsTruststorePassword},type=PKCS12)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm=\"SunX509\",credential-reference={store=defaultCS, alias=httpsKeystorePassword})'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/server-ssl-context=https:add(key-manager=httpsKM,protocols=[\"TLSv1.3\",\"TLSv1.2\"],use-cipher-suites-order=false,cipher-suite-filter=\"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\",cipher-suite-names=\"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256\",trust-manager=httpsTM,want-client-auth=true,authentication-optional=true)'"

  show "# Add HTTP(S) listeners"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding=\"http\", redirect-socket=\"https\")'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=https:add(socket-binding=\"https\", ssl-context=\"https\", max-parameters=2048)'"
  run_cmd "/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"
fi

show "# Create the Credential Store"
run_cmd "sudo mkdir -p ${wildfly_dir}/standalone/configuration/keystore"
if [ -f "$EJBCA_HOME/p12/truststore.p12" ];
then
  run_cmd "sudo cp $EJBCA_HOME/p12/truststore.p12 ${install_dir}/wildfly-${version}/standalone/configuration/keystore/"
else
  echo "#"
  echo "#"
  echo "# WARNING!"
  echo "# You have not generated the p12/truststore.p12"
  echo "# This is done by running \"ant runinstall\" from the folder \"$EJBCA_HOME\""
  echo "# After that it needs to be copied into \"${install_dir}/wildfly-${version}/standalone/configuration/keystore/\""
  echo "#"
  echo "#"
fi

if [ -f "$EJBCA_HOME/p12/tomcat.p12" ];
then
  run_cmd "sudo cp $EJBCA_HOME/p12/tomcat.p12 ${install_dir}/wildfly-${version}/standalone/configuration/keystore/keystore.p12"
else
  echo "#"
  echo "#"
  echo "# WARNING!"
  echo "# You have not generated the p12/tomcat.p12"
  echo "# This is done by running \"ant runinstall\" from the folder \"$EJBCA_HOME\""
  echo "# After that it needs to be copied into \"${install_dir}/wildfly-${version}/standalone/configuration/keystore/\" and renamed to \"keystore.p12\"."
  echo "#"
  echo "#"
fi
run_cmd "sudo chown $wildflyuser:$wildflyuser ${wildfly_dir}/standalone/configuration/keystore"
