#!/bin/bash

set -e

export logfile="install.log"
rm -rf $logfile
rm -rf "wildfly.log"

run_cmd() {
  echo "\$ $1"
  eval $1
}

show() {
  echo "$1"
}

export wildfly_pid=$(sudo lsof -i :9990|sed 's/java\s*//g'|sed 's/\s.*//g'|grep -iv command)
if [ ! "x$wildfly_pid"="x" ];
then
  show "# WildFly is already running. Stop it."
  run_cmd "sudo kill $wildfly_pid"
fi

OPTSTRING=":d:i:u:"

# Some default options
db="mariadb"
install_dir="/opt"
wildflyuser=$(whoami)

while getopts ${OPTSTRING} opt; do
  case ${opt} in
    d)
      export db=${OPTARG}
      ;;
    i)
      install_dir=${OPTARG}
      ;;
    u)
      wildflyuser=${OPTARG}
      ;;
    :)
      show "Option -${OPTARG} requires an argument."
      run_cmd "exit 1"
      ;;
    ?)
      show "Invalid option: -${OPTARG}."
      run_cmd "exit 1"
      ;;
  esac
done

install_dir=$(echo $install_dir | sed -s 's|//|/|')
show "# Database               : ${db}"
show "# Installation directory : ${install_dir}"
show "# WildFly user           : ${wildflyuser}"
run_cmd "mkdir -p ${install_dir}"

export zipfile="wildfly-32.0.0.Final.zip"
show "# Downloading Wildfly32"

run_cmd "rm -rf /tmp/${zipfile}"
run_cmd "wget https://github.com/wildfly/wildfly/releases/download/32.0.0.Final/${zipfile} -O /tmp/${zipfile}"

show "# Unpacking Wildfly32 into ${install_dir}"
run_cmd "sudo rm -rf ${install_dir}/wildfly"
run_cmd "sudo rm -rf ${install_dir}/wildfly-32.0.0.Final"
run_cmd "sudo unzip -q /tmp/${zipfile} -d ${install_dir}/"
run_cmd "sudo ln -snf ${install_dir}/wildfly-32.0.0.Final ${install_dir}/wildfly"
run_cmd "sudo rm -rf /tmp/${zipfile}"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly-32.0.0.Final"

show "# Remove RESTEasy-Crypto"
run_cmd "sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' ${install_dir}/wildfly/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml"
run_cmd "rm -rf ${install_dir}/wildfly/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/"

show "# Create a Custom Configuration"
run_cmd "cp standalone.conf ${install_dir}/wildfly/bin/"
run_cmd "sed -i -e 's/{{ HEAP_SIZE }}/2048/g' ${install_dir}/wildfly/bin/standalone.conf"
export random_string=$(od -A n -t d -N 1 /dev/urandom | tr -d ' ')
run_cmd "sed -i -e \"s/{{ TX_NODE_ID }}/$random_string/g\" ${install_dir}/wildfly/bin/standalone.conf"

show "# Start WildFly"
show "$ ${install_dir}/wildfly/bin/standalone.sh 2>&1 1>wildfly.log &"
# Warning! Don't make any function-call to 'run_cmd' with command ending with '&'
export current_dir=$(pwd)
pushd ${install_dir}/wildfly/bin/
./standalone.sh 2>&1 1>$current_dir/wildfly.log &
popd
run_cmd "sleep 5"
export wildfly_pid=$(sudo lsof -i :9990|sed 's/java\s*//g'|sed 's/\s.*//g'|grep -iv command)
show "# PID=$wildfly_pid"

show "# Create an Elytron Credential Store"

show "# Create a Master Password"
run_cmd "rm -rf wildfly_pass"
run_cmd "echo '#!/bin/sh' > wildfly_pass"
run_cmd "echo \"echo '$(openssl rand -base64 24)'\" >> wildfly_pass"
run_cmd "sudo rm -rf /usr/bin/wildfly_pass"
run_cmd "sudo mv wildfly_pass /usr/bin/"
run_cmd "sudo chown $wildflyuser:$wildflyuser /usr/bin/wildfly_pass"
run_cmd "sudo chmod 700 /usr/bin/wildfly_pass"

show "# Create the Credential Store"
run_cmd "sudo mkdir -p ${install_dir}/wildfly/standalone/configuration/keystore"
run_cmd "sudo chown $wildflyuser:$wildflyuser ${install_dir}/wildfly/standalone/configuration/keystore"

# This is a bug in WildFly. https://stackoverflow.com/questions/28254956/duplicate-resource-wildfly
set +e
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add(path=keystore/credentials, relative-to=jboss.server.config.dir, credential-reference={clear-text=\"{EXT}/usr/bin/wildfly_pass\", type=\"COMMAND\"}, create=true)'"

show "# Configure WildFly Remoting"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)'"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)'"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)'"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect ':reload'"

show "# Configure logging"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.ejbca:add(level=INFO)'"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.cesecore:add(level=INFO)'"
run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=com.keyfactor:add(level=INFO)'"

set -e

# echo "* Configure firewall"
# sudo ufw enable
# systemctl enable firewalld --now
# firewall-cmd --set-default-zone=dmz
# firewall-cmd --zone=dmz --permanent --add-port 8080/tcp
# firewall-cmd --zone=dmz --permanent --add-port 8443/tcp
# firewall-cmd --reload

show "# Make sure it is possible to copy new files into deployments folder"
run_cmd "sudo chmod 777 ${install_dir}/wildfly/standalone/deployments"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly"
run_cmd "sudo chown -R $wildflyuser:$wildflyuser ${install_dir}/wildfly-32.0.0.Final"

# Warning!
# It is important to first download the driver completely to a folder outside of the the Wildfly deployment folder
# and then copy it into the WildFly deployment folder. Otherwise WildFly will try to extract it before the jar-file
# is downloaded and thereby think it is empty.

case $db in
  mariadb)
    show "# Downloading driver for MariaDB"
    run_cmd "wget https://dlm.mariadb.com/3852266/Connectors/java/connector-java-3.4.1/mariadb-java-client-3.4.1.jar -O mariadb-java-client.jar"
    run_cmd "mv mariadb-java-client.jar ${install_dir}/wildfly/standalone/deployments/"

    show "# Adding datasource"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect 'data-source add --name=ejbcads --connection-url=\"jdbc:mysql://127.0.0.1:3306/ejbca?permitMysqlScheme\" --jndi-name=\"java:/EjbcaDS\" --use-ccm=true --driver-name=\"mariadb-java-client.jar\" --driver-class=\"org.mariadb.jdbc.Driver\" --user-name=\"ejbca\" --credential-reference={store=defaultCS, alias=dbPassword} --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql=\"select 1;\"'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect ':reload'"
    ;;
  postgres)
    show "# Downloading driver for PostgreSQL"
    run_cmd "wget https://jdbc.postgresql.org/download/postgresql-42.2.18.jar -O postgresql-jdbc4.jar"
    run_cmd "mv postgresql-jdbc4.jar ${install_dir}/wildfly/standalone/deployments/"

    show "# Adding datasource"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect 'data-source add --name=ejbcads --connection-url=\"jdbc:postgresql://127.0.0.1/ejbca\" --jndi-name=\"java:/EjbcaDS\" --use-ccm=true --driver-name=\"postgresql.jar\" --driver-class=\"org.postgresql.Driver\" --user-name=\"ejbca\" --credential-reference={store=defaultCS, alias=dbPassword} --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql="select 1;"'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect ':reload'"
    ;;
  mssql)
    show "# Downloading driver for MSSQL"
    run_cmd "wget https://github.com/microsoft/mssql-jdbc/releases/download/v12.8.1/mssql-jdbc-12.8.1.jre11.jar -O mssql-jdbc.jre11.jar"
    run_cmd "mv mssql-jdbc.jre11.jar ${install_dir}/wildfly/standalone/deployments/"

    show "# Adding datasource"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"ejbca\")'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect '/subsystem=datasources/data-source=ejbcads:add(connection-url=\"jdbc:sqlserver://foobar.YOUR.DOMAIN:1433;DatabaseName=ejbca;encrypt=true;trustServerCertificate=false;hostNameInCertificate=*.database.windows.net;loginTimeout=30;sendStringParametersAsUnicode=false\", min-pool-size=5, max-pool-size=150, jndi-name=\"java:/EjbcaDS\", driver-name=mssql-jdbc.jre11.jar, user-name=\"ejbca\", credential-reference={store=defaultCS, alias=dbPassword}, pool-prefill=false, pool-use-strict-min=false, idle-timeout-minutes=2)'"
    run_cmd "${install_dir}/wildfly/bin/jboss-cli.sh --connect ':reload'"
    ;;
  *)
    show "${db} is an unknown database. Valid options are: mariadb, postgres and mssql."
    run_cmd "exit 1"
    ;;
esac

show "# Stop WildFly"
run_cmd "sudo kill $wildfly_pid"
