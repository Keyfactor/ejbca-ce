#!/bin/bash

########################################################################################
#
#    Copyright 2017 by Christian Felsing <support@felsing.net>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
########################################################################################
#
# Original at GitHub: https://github.com/ip6li/ejbca-setup
# 
# This script modified by EJBCA Team to run on a local EJBCA package
#
########################################################################################
#     #     #     ######   #     #  ###  #     #   #####   
#  #  #    # #    #     #  ##    #   #   ##    #  #     #  
#  #  #   #   #   #     #  # #   #   #   # #   #  #        
#  #  #  #     #  ######   #  #  #   #   #  #  #  #  ####  
#  #  #  #######  #   #    #   # #   #   #   # #  #     #  
#  #  #  #     #  #    #   #    ##   #   #    ##  #     #  
 ## ##   #     #  #     #  #     #  ###  #     #   #####   

# THIS SCRIPT WILL DESTROY EXISTING EJBCA INSTALLATION
# YOU HAVE BEEN WARNED
########################################################################################


########################################################################################

# Configurables
httpsserver_hostname="localhost"
database_host="localhost"
database_name="ejbcatest"
database_driver="org.mariadb.jdbc.Driver"
database_url="jdbc:mysql://${database_host}:3306/${database_name}?characterEncoding=UTF-8"
database_username="ejbca"
database_password="ejbca"
BASE_DN="O=Example CA,C=SE"

# Variables that should not be configured
superadmin_cn="SuperAdmin"
ca_name="ManagementCA"
ca_dn="CN=ManagementCA,${BASE_DN}"

ejbca_user=$(whoami)
ejbca_group=$(id -g -n $ejbca_user)
ejbca_user_home=~

# Full path to where we run the script, which will be where we unpack and install software
INSTALL_DIRECTORY=$(pwd)
# The name of the EJBCA directory
startdirectory=$(cd "$(dirname "$0")"; pwd -P)
EJBCA_DIRECTORY=$(echo "$startdirectory" | sed 's/\/bin\/.*//')

mysql_root_user="root"

WILDFLY_VERSION="10.1.0.Final"
#EJBCA_VERSION="6_5.0.5"
MARIADB_CONNECTOR_VERSION="2.2.0"

#EJBCA_DOWNLOAD_URL="https://downloads.sourceforge.net/project/ejbca/ejbca6/ejbca_6_5_0/ejbca_ce_${EJBCA_VERSION}.zip"
#EJBCA_DOWNLOAD_SHA256=85c09d584896bef01d207b874c54ae2f994d38dd85b40fd10c21f71f7210be8a
#EJBCA_DOWNLOAD_SHA256_URL="https://downloads.sourceforge.net/project/ejbca/ejbca6/ejbca_6_5_0/ejbca_ce_${EJBCA_VERSION}.zip.SHA-256"

MARIADB_DOWNLOAD_URL="https://downloads.mariadb.com/Connectors/java/connector-java-${MARIADB_CONNECTOR_VERSION}/mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar"
MARIADB_DOWNLOAD_SHA256=fead0b3c61eba772fdaef2abed3b80eaeadbb5706abd78acf7698fe0a871cd4c
#MARIADB_DOWNLOAD_SHA256_URL="https://downloads.mariadb.com/Connectors/java/connector-java-${MARIADB_CONNECTOR_VERSION}/sha256sums.txt"

WILDFLY_TAR="wildfly-${WILDFLY_VERSION}.tar.gz"
WILDFLY_TAR_SHA256=80781609be387045273f974662dadf7f64ad43ee93395871429bc6b7786ec8bc
WILDFLY_DIR="wildfly-${WILDFLY_VERSION}"
WILDFLY_DOWNLOAD_URL=https://download.jboss.org/wildfly/${WILDFLY_VERSION}/${WILDFLY_TAR}

# Which OS are we running? RHEL or UBUNTU? This is updated automagically in the end of this script
BASE_OS=UBUNTU

########################################################################################

pwgen() {
  NEW_PASSWORD=$(dd if=/dev/urandom bs=1 count=64 2> /dev/null | sha1sum | awk '{print $1}' | tr -d "\n")
  if [ -z "$NEW_PASSWORD" ]; then
    echo "Created empty password - very bad"
    exit 1
  fi
  echo -n "${NEW_PASSWORD}"
}

cakeystorepass=$(pwgen)
truststorepass=$(pwgen)
httpsserver_password=$(pwgen)
cmskeystorepass=$(pwgen)
passwordencryptionkey=$(pwgen)
superadmin_password=$(pwgen)

init_mysql() {
  cd $INSTALL_DIRECTORY || exit 1
  mysql_host=$(grep database.url ejbca-custom/conf/database.properties | awk -F/ '{print $3}' | awk -F: '{print $1}' | grep -v '^$')
  echo "Dropping all database tables in database ${database_name} (using the script ejbca/doc/sql-scripts/drop-tables-ejbca-mysql.sql), using DB user ${database_username}, who should have privileges to do that"
  cat ejbca/doc/sql-scripts/drop-tables-ejbca-mysql.sql | mysql --host=${database_host} --user=${database_username} --password=${database_password} ${database_name} -f
}


create_mysql_index() {
  cd $INSTALL_DIRECTORY || exit 1
  cat ejbca/doc/sql-scripts/create-index-ejbca.sql | mysql --host=${database_host} --user=${database_username} --password=${database_password} ${database_name}
}


wildfly_killall() {
  pidof java > /dev/null 2> /dev/null
  if [ $? -eq 0 ]; then
    echo "There are Java processes running, make sure there is no WildFly, JBoss or Tomcat server already running, installation will fail if so."
    echo "Are you sure you want to continue?"
    select yn in "Yes" "No"; do
      case $yn in
          Yes ) echo "Continuing..."; break;;
          No ) exit;;
      esac
    done
#    killall -9 java
#    sleep 10
  fi
}


wildfly_exec() {
  wildfly/bin/jboss-cli.sh --connect "$1"
}


wildfly_shutdown() {
  cd $INSTALL_DIRECTORY || exit 1
  wildfly/bin/jboss-cli.sh --connect command=:shutdown
}


wildfly_reload() {
  cd $INSTALL_DIRECTORY || exit 1
  wildfly/bin/jboss-cli.sh --connect command=:reload
}


wildfly_check() {
  DURATION_SECONDS=30
  if [ ! -z "$1" ]; then
    DURATION_SECONDS="$1"
  fi
  DURATION=$(echo "$DURATION_SECONDS / 5" | bc)

  echo "wait ${DURATION_SECONDS}s for start up wildfly"
  cd $INSTALL_DIRECTORY || exit 1
  for i in `seq 1 $DURATION`; do
    wildfly/bin/jboss-cli.sh --connect ":read-attribute(name=server-state)" | grep "result" | awk '{ print $3; }'|grep running
    if [ $? -eq 0 ]; then
      return 0
    fi
    sleep 5
  done
  echo "wildfly not started after ${DURATION_SECONDS}s, exit"
  exit 1
}


ejbca_deploy_check() {
  cd $INSTALL_DIRECTORY
  DURATION_SECONDS=30
  if [ ! -z "$1" ]; then
    DURATION_SECONDS="$1"
  fi
  DURATION=$(echo "$DURATION_SECONDS / 5" | bc)

  echo "wait ${DURATION_SECONDS}s for deploying EJBCA"
  cd $INSTALL_DIRECTORY || exit 1
  for i in `seq 1 $DURATION`; do
    if [ -f wildfly/standalone/deployments/ejbca.ear.deployed ]; then
      echo "EJBCA deployed"
      return 0
    fi
    sleep 5
  done
  echo "EJBCA not deployed after ${DURATION_SECONDS}s, exit"
  exit 1
}


wildfly_register_database() {
  wildfly/bin/jboss-cli.sh --connect "/subsystem=datasources/jdbc-driver=org.mariadb.jdbc.Driver:add(driver-name=org.mariadb.jdbc.Driver,driver-module-name=org.mariadb,driver-xa-datasource-class-name=org.mariadb.jdbc.MariaDbDataSource)"
  wildfly_reload
}


wildfly_enable_ajp() {
  wildfly/bin/jboss-cli.sh --connect "/subsystem=undertow/server=default-server/ajp-listener=ajp-listener:add(socket-binding=ajp, scheme=https, enabled=true)"
}


wildfly_setup_https() {
  cd $INSTALL_DIRECTORY || exit 1

  wildfly_server_config_dir="wildfly/standalone/configuration"
  keystore_password=$(grep '^httpsserver.password' ejbca-custom/conf/web.properties | awk -F= '{ print $2 }' | grep -v '^$')
  truststore_pass=$(grep '^java.trustpassword' ejbca-custom/conf/web.properties | awk -F= '{ print $2 }' | grep -v '^$')
  web_hostname=$(grep '^httpsserver.hostname' ejbca-custom/conf/web.properties | awk -F= '{ print $2 }' | grep -v '^$')

  wildfly_exec "/interface=http:add(inet-address=\"0.0.0.0\")"
  wildfly_exec "/interface=httpspub:add(inet-address=\"0.0.0.0\")"
  wildfly_exec "/interface=httpspriv:add(inet-address=\"0.0.0.0\")"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=http:add(port="8080",interface=\"http\")"
  wildfly_exec "/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding=http)"
  wildfly_exec "/subsystem=undertow/server=default-server/http-listener=http:write-attribute(name=redirect-socket, value=\"httpspriv\")"
  wildfly_exec ":reload"
  
  wildfly_check
  
  wildfly_exec "/core-service=management/security-realm=SSLRealm:add()"
  wildfly_exec "/core-service=management/security-realm=SSLRealm/server-identity=ssl:add(keystore-relative-to=\"jboss.server.config.dir\", keystore-path=\"keystore/keystore.jks\", keystore-password=\"${keystore_password}\", alias=\"${web_hostname}\")"
  wildfly_exec "/core-service=management/security-realm=SSLRealm/authentication=truststore:add(keystore-relative-to=\"jboss.server.config.dir\", keystore-path=\"keystore/truststore.jks\", keystore-password=\"${truststore_pass}\")"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=httpspriv:add(port="8443",interface=\"httpspriv\")"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=httpspub:add(port="8442", interface=\"httpspub\")"

  wildfly_exec ":shutdown"
  nohup wildfly/bin/standalone.sh -b 0.0.0.0 > /dev/null 2> /dev/null &
  wildfly_check 240

  wildfly_exec "/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding=httpspriv, security-realm=\"SSLRealm\", verify-client=REQUIRED)"
  wildfly_exec "/subsystem=undertow/server=default-server/https-listener=httpspub:add(socket-binding=httpspub, security-realm=\"SSLRealm\")"
  wildfly_exec ":reload"
  wildfly_check 30

  wildfly_exec "/system-property=org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH:add(value=true)"
  wildfly_exec "/system-property=org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH:add(value=true)"
  wildfly_exec "/system-property=org.apache.catalina.connector.URI_ENCODING:add(value=\"UTF-8\")"
  wildfly_exec "/system-property=org.apache.catalina.connector.USE_BODY_ENCODING_FOR_QUERY_STRING:add(value=true)"
  wildfly_exec "/subsystem=webservices:write-attribute(name=wsdl-host, value=jbossws.undefined.host)"
  wildfly_exec "/subsystem=webservices:write-attribute(name=modify-wsdl-address, value=true)"
  wildfly_exec ":reload"
  wildfly_check 30
}


wildfly_setup_logging() {
  wildfly_exec "/subsystem=logging/logger=org.ejbca:write-attribute(name=level, value=DEBUG)"
  wildfly_exec "/subsystem=logging/logger=org.cesecore:write-attribute(name=level, value=DEBUG)"
  wildfly_exec ":reload"
  wildfly_check 30
}


ejbca_installer() {
  cd $INSTALL_DIRECTORY
  #rm -f /tmp/run_as_root.sh

  wildfly_killall

  create_config_files

#  if [ ! -f Download/ejbca_ce_${EJBCA_VERSION}.zip ]; then
#    cd Download
#    echo "Downloading EJBCA ${EJBCA_VERSION}"
#    curl -o ejbca_ce_${EJBCA_VERSION}.zip -L "${EJBCA_DOWNLOAD_URL}"
#    curl -o ejbca_ce_${EJBCA_VERSION}.zip.sha256 -L "${EJBCA_DOWNLOAD_SHA256_URL}"
#    sha256sum --check ejbca_ce_6_5.0.5.zip.sha256
#    echo ${EJBCA_DOWNLOAD_SHA256} ejbca_ce_${EJBCA_VERSION}.zip > ejbca_ce_${EJBCA_VERSION}.zip.sha256
#    sha256sum --check ejbca_ce_${EJBCA_VERSION}.zip.sha256
#    if [ $? -ne 0 ]; then
#       echo "SHA256 for EJBCA does not match"
#       exit 1
#    fi
#    rm ejbca_ce_${EJBCA_VERSION}.zip
#    cd ..
#  fi

#  unzip Download/ejbca_ce_${EJBCA_VERSION}.zip || exit 1
  if [ -h ejbca ]; then
    rm -f ejbca
  fi
  if [ ! -d ejbca ]; then
#    ln -s ejbca_ce_${EJBCA_VERSION} ejbca
    ln -s ${EJBCA_DIRECTORY} ejbca
  fi

  echo
  echo "Init database"
  init_mysql

  if [ ! -d Download ]; then
    mkdir Download
  fi
  
  echo
  echo "Downloading(if needed) and unpacking WildFly"
  if [ ! -f Download/${WILDFLY_TAR} ]; then
    cd Download
    echo "Downloading WildFly to $(pwd)"
    curl -o ${WILDFLY_TAR} -L ${WILDFLY_DOWNLOAD_URL}
    echo ${WILDFLY_TAR_SHA256} ${WILDFLY_TAR} > ${WILDFLY_TAR}.sha256
    sha256sum --check ${WILDFLY_TAR}.sha256
    if [ $? -ne 0 ]; then
       echo "SHA256 for wildfly does not match"
       rm ${WILDFLY_TAR}
       exit 1
    fi
    cd ..
  fi
  
  if [ ! -f Download/mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar ]; then
    cd Download
    echo "Downloading MariaDB Java Connector to $(pwd)"
    curl -o mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar -L ${MARIADB_DOWNLOAD_URL}
#    curl -o mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.sha256 -L ${MARIADB_DOWNLOAD_SHA256_URL}
#    sha256sum --check mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.sha256 2>&1| grep mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar
    echo ${MARIADB_DOWNLOAD_SHA256} mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar > mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar.sha256
    sha256sum --check mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar.sha256
    if [ $? -ne 0 ]; then
       echo "SHA256 for mariadb-java-client does not match"
       rm mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar
       exit 1
    fi
    cd ..
  fi
  
  rm -rf "${WILDFLY_DIR}" > /dev/null 2> /dev/null
#  rm -rf "ejbca_ce_${EJBCA_VERSION}" > /dev/null 2> /dev/null
  
  tar xvf Download/${WILDFLY_TAR}
  if [ -h wildfly ]; then
    rm -f wildfly
  fi
  ln -s "${WILDFLY_DIR}" wildfly
  
  cp "Download/mariadb-java-client-${MARIADB_CONNECTOR_VERSION}.jar" "wildfly/standalone/deployments/mariadb-java-client.jar" || exit 1
  
  echo
  echo "Configuring WildFly"

  # patch standalone.conf
  cd $INSTALL_DIRECTORY/wildfly/bin || exit 1
  sed -i.bak 's/JAVA_OPTS="-Xms64m -Xmx512m -XX:MaxPermSize=256m -Djava.net.preferIPv4Stack=true"/JAVA_OPTS="-Xms2048m -Xmx2048m -XX:MaxPermSize=384m -Djava.net.preferIPv4Stack=true"/g' standalone.conf
  cd $INSTALL_DIRECTORY
  
  nohup wildfly/bin/standalone.sh -b 0.0.0.0 > /dev/null 2> /dev/null &
  sleep 3
  wildfly_check || exit 1
  #wildfly_register_database || exit 1
  wildfly_enable_ajp || exit 1
  wildfly_reload || exit 1
  wildfly_check || exit 1
  
  # Add datasource
  wildfly_exec "data-source add --name=ejbcads --driver-name=\"mariadb-java-client.jar\" --connection-url=\"jdbc:mysql://${mysql_host}:3306/${database_name}\" --jndi-name=\"java:/EjbcaDS\" --use-ccm=true --driver-class=\"org.mariadb.jdbc.Driver\" --user-name=\"${database_username}\" --password=\"${database_password}\" --validate-on-match=true --background-validation=false --prepared-statements-cache-size=50 --share-prepared-statements=true --min-pool-size=5 --max-pool-size=150 --pool-prefill=true --transaction-isolation=TRANSACTION_READ_COMMITTED --check-valid-connection-sql=\"select 1;\""
  wildfly_exec ":reload"
  
  # Configure WildFly Remoting
  wildfly_exec "/subsystem=remoting/http-connector=http-remoting-connector:remove"
  wildfly_exec "/subsystem=remoting/http-connector=http-remoting-connector:add(connector-ref=\"remoting\",security-realm=\"ApplicationRealm\")"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=\"4447\")"
  wildfly_exec "/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting)"
  wildfly_exec ":reload"
  
  # Configure logging
  wildfly_exec "/subsystem=logging/logger=org.ejbca:add"
  wildfly_exec "/subsystem=logging/logger=org.ejbca:write-attribute(name=level, value=DEBUG)"
  wildfly_exec "/subsystem=logging/logger=org.cesecore:add"
  wildfly_exec "/subsystem=logging/logger=org.cesecore:write-attribute(name=level, value=DEBUG)"
  
  # Remove existing TLS and HTTP configuration
  wildfly_exec "/subsystem=undertow/server=default-server/http-listener=default:remove"
  wildfly_exec "/subsystem=undertow/server=default-server/https-listener=https:remove"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=http:remove"
  wildfly_exec "/socket-binding-group=standard-sockets/socket-binding=https:remove"
  wildfly_exec ":reload"
  
  echo
  echo "Deploying EJBCA"

  cd ejbca || exit 1
  ant clean deployear
  
  ejbca_deploy_check 240
  cd ejbca || exit 1
  echo "starting EJBCA initialization"
  ant runinstall

  echo "deploy keystore"
  cd $INSTALL_DIRECTORY
  wildfly_check || exit 1
  cd ejbca || exit 1
  ant deploy-keystore
  
  cp -a p12 ../ejbca-custom/

  cd $INSTALL_DIRECTORY || exit 1
  #wildfly_exec ":shutdown"
  #nohup wildfly/bin/standalone.sh -b 0.0.0.0 > /dev/null 2> /dev/null &
  #wildfly_check 240

  echo "creating SQL index"
  create_mysql_index

  echo "set up Wildfly https connectors"
  wildfly_setup_https

  echo "set up Wildfly logging"
  wildfly_setup_logging

  echo "*********************************************************************"
  echo "* SUCCESS                                                           *"
  echo "*********************************************************************"
}


are_you_sure() {
  echo "LAST CHANCE TO STOP THIS"
  echo "Do you really want to destroy your EJBCA installation in database $database_name?"
  select yn in "Yes" "No"; do
    case $yn in
        Yes ) ejbca_installer; break;;
        No ) exit;;
    esac
  done
}


init_installer() {
  echo "This will destroy your complete EJBCA installation in database $database_name"
  echo "Do you want this?"
  select yn in "Yes" "No"; do
      case $yn in
          Yes ) are_you_sure; break;;
          No ) exit;;
      esac
  done
}


create_config_files() {
mkdir -p ejbca-custom/conf || exit 1

cat <<EOF > ejbca-custom/conf/batchtool.properties
# Property file used to configure the batch tool for generating
# keystores. This file should be in either current directory or conf/ 
# subdirectory or in your home directory if personlized settings is 
# required. If no property file is found,default values will be used.

# Indicates which type of keys should be generated by the batch tool
# Examples: RSA, ECDSA or DSA
#
# Default: RSA
keys.alg=RSA

# Indicates which key size of the RSA or DSA keys that should be used, or curve if ECDSA.
# Examples: 1024 for RSA or DSA and prime256v1 for ECDSA
#
# Default: 2048
keys.spec=2048
EOF

cat <<EOF > ejbca-custom/conf/cesecore.properties
# Set to true to allow dynamic re-configuration using properties files in the file 
# system. Using this you can place a file /etc/cesecore/conf/cesecore.properties in the file system and
# override default values compiled into ejbca.ear.
#
# Default: false
#allow.external-dynamic.configuration=false

# -------------- NOTE for Upgrades --------------
# When upgrading, the important options are:
# - ca.keystorepass
# - password.encryption.key
# - ca.cmskeystorepass (in ejbca.properties)

# -------------- General security --------------
# The following key (strictly speaking, PBE input password) allows for encrypting passwords used in EJBCA (e.g. End Entity and Crypto Token
#   passwords stored in database).
# This property should be set before initial EJBCA installation and it should't be changed later, because there could exist
#   passwords encrypted with the key about to be changed and EJBCA would be unable to decrypt them (note that the current implementation
#   is capable to try decryption with the default key, i.e. qhrnf.f8743;12%#75, but it won't be able to decrypt passwords encrypted
#   with a custom key being replaced for another custom key).
# For setting this property you could use any password you consider safe, but it is strongly recommended that you use a randomly
#   generated password, e.g. by using `openssl rand -base64 24`.
#
# When upgrading a 100% up-time cluster all nodes must produce password encryption that is decryptable by old nodes.
# When all nodes run EJBCA 6.8.0 or higher you can change the password, and count, to increase security when passwords are saved in clear text.
# (mostly used for batch generation and auto-activation) 
#
# Default: qhrnf.f8743;12%#75
password.encryption.key=${passwordencryptionkey}

# Nr of rounds when creating password based encryption keys (PBE).
# To be able to change this you also need to set password.encryption.key to something other than the default (with applicable 100% uptime consideration). 
#password.encryption.count=100

# ------------ Basic CA configuration ---------------------
# When upgrading, the important options are:
# - ca.keystorepass
# - ca.cmskeystorepass (in ejbca.properties)

# This password is used internally to protect CA keystores in database (i.e. the CAs private key).
# foo123 is to keep compatibility with default installations of EJBCA 3.0, please change this if possible
# Note! If changing this value AFTER installation of EJBCA you must do 'ant clean; ant bootstrap' in order to activate changes.
ca.keystorepass=${cakeystorepass}

# Default Random Number Generator algorithm for certificate serial number generation.
# Available algorithms are:
# SHA1PRNG
ca.rngalgorithm=SHA1PRNG

# The length in octets of certificate serial numbers generated. 8 octets is a 64 bit serial number.
# It is really recommended to use at least 64 bits, so please leave as default unless you are really sure, 
# and have a really good reason to change it.
# Possible values: between 4 and 20
# Default: 8
#ca.serialnumberoctetsize=8

# The date and time from which an expire date of a certificate is to be considered to be too far in the future.
# The time could be specified in two ways:
# 1. The unix time see http://en.wikipedia.org/wiki/Unix_time given as an integer decoded to an hexadecimal string.
#    The value 80000000 will give the time when the integer becomes negative if casted to 32 bit.
#    This is when the year 2038 problem occurs. See http://en.wikipedia.org/wiki/Year_2038_problem .
#    Set to this value if you don't want to issue any certificates that could cause this problem.
# 2. For you convenience this could also be specified in the ISO8601 date format.
# Default: no limitation
# The 2038 problem:
#ca.toolateexpiredate=80000000
#ca.toolateexpiredate=2038-01-19 03:14:08+00:00


# The idea of a HSM to use a HSM is to have the private keys protected. It should not be possible to extract them.
# To prevent using a key with the private part extractable a test is made before activating a CA.
# If this test shows that you can read the private part from the key the CA will not be activated unless the key is a SW key.
# You may (but should not) permit using extractable private keys by setting this property to 'true'.
# Default: false
#ca.doPermitExtractablePrivateKeys=true

# Forbidden characters in DB.
# When one of these characters is found in any string that should be stored in
# the DB it will be replaced by a forward slash (/). Same replacement will also
# be done when searching for strings in the DB.
# Example of strings affected by this:
# * user names
# * issuer and subject DN of certificates.
# * profile names
# It will also be impossible to use any of these characters in any field of a
# certificate (like issuer or subject DN).
# It is strongly discouraged to change this property. Instead set it to the
# desired value before you install EJBCA.
# If you change these characters later it might be that some search for a string
# that include one of the characters that have been changed will fail. This could
# result in that some important functionality stops working. Examples what could
# fail is:
# * An administrator user can not be used any more.
# * A certificate can not be found.
# * A certificate can not be issued since the used profile can not be found.
# The default are these characters: '\\n', '\\r', ';', '!', '\\0', '%', '\`', '?', '$', '~'.
# The property value is a string with all forbidden characters concatenated
# (without any space). Note that '\\' is an escape character.
# This will be the same as not defining the property:
#forbidden.characters = \\n\\r;!\\u0000%\`?$~
# And nothing forbidden will be:
#forbidden.characters  =

# ------------- Core language configuration -------------
# The language that should be used internally for logging, exceptions and approval notifications.
# The languagefile is stored in 'src/intresources/ejbcaresources.xx.properties' and 'intresources.xx.properties'.
# Should be one of: en, fr, ja, pt, sv.
# Default: en
intresources.preferredlanguage=en

# The language used internally if a resource not found in the preferred language.
# Default: sv
intresources.secondarylanguage=en

# ------------ Audit log configuration ---------------------
# I you want to use integrity protection of the audit log (in the IntegrityProtectedDevice) you
# must also configure integrity protection in conf/databaseprotection.properties
# 

#### Secure audit log configuration.

# All security log events are written to all enabled/configured devices.
# The following AuditLogDevice implementations are available:
#securityeventsaudit.implementation.X=org.cesecore.audit.impl.log4j.Log4jDevice
#securityeventsaudit.implementation.X=org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice

# Default is to use the Log4jDevice and the IntegrityProtectedDevice (without integrity protection enabled),
# To de-configure these devices, set their implementation to "null" value (don't forget to comment out default section below).
# i.e.
#securityeventsaudit.implementation.0=null
securityeventsaudit.implementation.1=null

# Each device can have a different exporter.
# The following AuditExporter implementations are available:
#securityeventsaudit.exporter.X=org.cesecore.audit.impl.AuditExporterDummy (default)
#securityeventsaudit.exporter.X=org.cesecore.audit.impl.AuditExportCsv
#securityeventsaudit.exporter.X=org.cesecore.audit.impl.AuditExporterXml

# Device implementation specific parameters (e.g. "key.subkey=value") can be passed by using 
#securityeventsaudit.deviceproperty.X.key.subkey=value

# Example configuration of Log4jDevice that logs to log4j server log file.
# The Log4jDevice does not support query, validation or export operations
securityeventsaudit.implementation.0=org.cesecore.audit.impl.log4j.Log4jDevice

# Example configuration of IntegrityProtectedDevice that logs to the database
# With XML export to /tmp/ (default export dir)
# On windows a path would be for example 'C:/Temp/'
#securityeventsaudit.implementation.1=org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice
#securityeventsaudit.exporter.1=org.cesecore.audit.impl.AuditExporterXml
#securityeventsaudit.deviceproperty.1.export.dir=/tmp/
#securityeventsaudit.deviceproperty.1.export.fetchsize=1000
#securityeventsaudit.deviceproperty.1.validate.fetchsize=1000

# Nodeid used for integrity protected audit log. If not set the hostname of local host is used.
# Default: not set
#cluster.nodeid=

# When upgrading a 100% up-time cluster, all nodes should be deployed with db.keepjbossserialization=true.
# For upgrades from EJBCA version 4.0 to later versions.
# Once all nodes are running > 4.0, set to false to increase efficiency and portability.
# Default: false
#db.keepjbossserialization=true

# Option if we should keep internal CA keystores in the CAData table to be compatible with CeSecore 1.1/EJBCA 5.0.
# Default to true. Set to false when all nodes in a cluster have been upgraded to CeSecore 1.2/EJBCA 5.1 or later,
# then internal keystore in CAData will be replaced with a foreign key in to the migrated entry in CryptotokenData.
#
# When upgrading a 100% up-time cluster, all nodes should initially be deployed with db.keepinternalcakeystores=true.
# Once all nodes are running > EJBCA 5.0, set to false again to increase efficiency and portability.
# For upgrades from EJBCA version 5.0 to later versions.
# Default: true
#db.keepinternalcakeystores=true

# When upgrading a 100% up-time cluster, all nodes should be deployed with ca.keepocspextendedservice=true.
# Once all nodes are running > 6.0, set to true to increase efficiency and portability.
# Default: false
#ca.keepocspextendedservice=true

# When generating large CRLs, the RAM of the Java process will limit how many entries that can be
# fetched from the database at the time. A small value will lead to multiple round-trips to the
# database and CRL generation will take more time.
#
# The heap usage can be estimated to roughly 600 bytes * rows per database read. The default of
# 0.5M revoked entries per database round trip will usually fit within a 2GiB heap assigned to the
# application server. If multiple large CRLs are generated at the same time, the used heap will be
# the sum of the heap used by each CRL generation.
#
# If you have plenty of RAM assigned to the application server you should increase this value.
# Default: 500000
#database.crlgenfetchsize=500000

#------------------- ECDSA implicitlyCA settings -------------
# Sets pre-defined EC curve parameters for the implicitlyCA facility.
# See the User's Guide for more information about the implicitlyCA facility.
# Setting these parameters are not necessary when using regular named curves. 
# if you don't know what this means, you can safely ignore these settings.
#
# Default values that you can experiment with:
# ecdsa.implicitlyca.q=883423532389192164791648750360308885314476597252960362792450860609699839
# ecdsa.implicitlyca.a=7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc
# ecdsa.implicitlyca.b=6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a
# ecdsa.implicitlyca.g=020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf
# ecdsa.implicitlyca.n=883423532389192164791648750360308884807550341691627752275345424702807307

#------------------- PKCS#11 -------------------------------------
# Configuration of PKCS#11 tokens.
#
# Disabling of sign mechanisms that are using PKCS#11 to hash the data before signing.
# If these mechanisms are disabled then the sun PKCS#11 wrapper will do the hashing
# before PKCS#11 is called.
# Default: true (the mechanisms are disabled).
#pkcs11.disableHashingSignMechanisms=false

# Caching the references to PKCS#11 objects can make a big performance difference.
# Default: true
#cryptotoken.keystorecache=true

# ------------------- Authentication Key Binding settings -------------------
# Configuration of available cipher suites for outgoing SSL/TLS connections
# that can be selected for an Authentication Key Binding.
# 
# Java 6: http://docs.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
#   TLS versions: SSLv3, TLSv1, SSLv2Hello
# Java 7: http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#SunJSSEProvider
#   TLS versions: SSLv3, TLSv1, SSLv2Hello, TLSv1.1, TLSv1.2
#   Cipher suites with SHA384 and SHA256 are available only for TLS 1.2 or later.
#
# The configuration format is "<TLS version>;cipher" and the follow ciphers are defined by default
# and can be undefined by setting the properties to "undefined".
#authkeybind.ciphersuite.0=TLSv1.2;TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
#authkeybind.ciphersuite.1=TLSv1.2;TLS_RSA_WITH_AES_256_CBC_SHA256
#authkeybind.ciphersuite.2=TLSv1.2;TLS_RSA_WITH_AES_128_CBC_SHA
#authkeybind.ciphersuite.3=TLSv1;TLS_DHE_RSA_WITH_AES_256_CBC_SHA
#authkeybind.ciphersuite.4=TLSv1;TLS_RSA_WITH_AES_256_CBC_SHA
#authkeybind.ciphersuite.5=TLSv1;TLS_RSA_WITH_AES_128_CBC_SHA


# ------------------- Certificate Transparency settings -------------------
# If your EJBCA has support for CT in it, you may configure caching of SCTs
# here. The cache is only used when using CT in OCSP responses (and not in
# the CT publisher or when using CT in new certificates).
#
# Enables or disables the cache.
# Default: true (caching enabled)
#ct.cache.enabled=false
#
# Maximum number of OCSP response extensions to cache, or -1 for no limit.
# You may need to adjust java heap parameters if you adjust this.
# Default: 100000
#ct.cache.maxentries=1000000
#
# Maximum frequency in milliseconds of clean ups when the cache is over its
# limit. During a clean up, cache entries are randomly queued for removal
# at the next clean up if they aren't used.
# Default: 10000 (10 seconds)
#ct.cache.cleanupinterval=60000
#
# Whether log availability should be tracked, and requests should "fast fail"
# whenever a log is known to be down. A log is "known to be down" when it
# is either unreachable or responds with an HTTP error status to a request.
# NOTE: Since a single error will cause ALL subsequent requests that are not
# cached to "fast fail" until the backoff time is over, make sure to:
#   1. Disallow CAs that are not trusted by the CT logs in CT-enabled
#      certificate profiles. If a log server receives a request for a
#      certificate from an untrusted CA, it will return an error, and trigger
#      "fail fail" for other certificates.
#   2. Make sure the certificate profiles are restrictive and do not allow
#      uncommon certificate fields etc., that could cause a parse error
#      in the CT log, which would also trigger fast fail.
# Default: false (fast fail disabled)
#ct.fastfail.enabled=true
#
# How long time (in milliseconds) EJBCA should wait until trying to use a log
# which has failed to respond to a request.
# Default: 1000 (1 second)
#ct.fastfail.backoff=60000
EOF


cat <<EOF > ejbca-custom/conf/database.properties
# ------------- Database configuration ------------------------

# The default values in this file is good for a default install, using the build in H2 test database, with JBoss 7/EAP 6.
# For a default install with Hypersonic database on JBoss 5, change database.name, database.url, database.driver and database.password.

# JNDI name of the DataSource used for EJBCA's database access. The prefix
# (e.g. 'java:/', '' or 'jdbc/')is automatically determined for each
# application server.
# default: EjbcaDS
#datasource.jndi-name=EjbcaDS

# The database name selected for deployment, used to copy XDoclet merge files.
# All supported databases are defined below, others can easily be added
# See the document doc/howto/HOWTO-database.txt for database specifics and tips and tricks.
# (Note that the names below are fixed for the database type, it is not the name of your database instance.)
# Default: h2
database.name=mysql

# Database connection URL.
# This is the URL used to connect to the database, used to configure a new datasource in JBoss.
# Default: jdbc:h2:~/ejbcadb;DB_CLOSE_DELAY=-1
database.url=${database_url}

# JDBC driver classname.
# The JEE server needs to be configured with the appropriate JDBC driver for the selected database
# The Default h2 works (as test database) on JBoss 7, on JBoss 5 use org.hsqldb.jdbcDriver
# Default: h2
database.driver=${database_driver}

# Database username.
# Default: sa (works with H2 on JBoss 7)
# Set to empty for hsql on JBoss 5
database.username=${database_username}

# Database password.
# Default: sa (works with H2 on JBoss 7)
# Set to empty for hsql on JBoss 5)
database.password=NOT_SHOWN

# The encoded certificate may be stored in the table Base64CertData instead of
# in a column in the CertificateData table. Using a separate table for the
# certificate data may speed up searching for certificates if there are lots of
# them (>100Million).
# Default: false
database.useSeparateCertificateTable=true
EOF


cat <<EOF > ejbca-custom/conf/ejbca.properties
#
# \$Id: ejbca.properties.sample 20512 2015-01-05 14:25:14Z mikekushner $
#
# This is a sample file to override properties used
# during development (or deployment) of EJBCA. Note that some properties
# have been moved to cesecore.properties.
# 
# You should copy and rename this file to ejbca.properties
# and customize at will.
#

# Application server home directory used during development. The path can not end with a slash or backslash.
# Default: \$APPSRV_HOME
appserver.home=${INSTALL_DIRECTORY}/wildfly

# See also the section 'cluster configuration' for other JBoss options, for example
# for deploying on JBoss EAP.

# Which application server is used? Normally this is auto-detected from 'appserver.home' and should not be configured. 
# Possible values: jboss, glassfish (, weblogic)
# Default: <auto-detect>
#appserver.type=jboss

# To prevent accidental runs of tests or deploying the wrong thing in a production environment, we
# could prevent this by setting this variable to either "true" or "false".
# Setting this value to 'false' will allow system tests to alter the configuration of the running
# EJBCA instance.
# Default: true
ejbca.productionmode=true
#ejbca.productionmode=false

# Set to true to allow dynamic re-configuration using properties files in the file 
# system. Using this you can place a file /etc/ejbca/conf/ocsp.properties in the file system and
# override default values compiled into ejbca.ear.
# Currently this works for most values in ejbca.properties, web.properties, cmp.properties, externalra-caservice.properties, ocsp.properties, extendedkeyusage.properties, jaxws.properties, xkms.properties
#
# Default: false
#allow.external-dynamic.configuration=false

# ------------ Basic CA configuration ---------------------
# Most CA options are configured in cesecore.properties, but some EJBCA-
# specific ones are configured here. When upgrading, the important options are:
# - ca.keystorepass (in cesecore.properties)
# - ca.cmskeystorepass

# Password used to protect CMS keystores in the database (CAs CMS signer/enc certificate).
# The default value is the same for convenience.
ca.cmskeystorepass=${cmskeystorepass}

# ------------- Approval configuration ------------------------
# Settings working as default values in the approval functionality
#
# Default request validity in seconds
# Default : 28800 (8 Hours)
#approval.defaultrequestvalidity=28800
#approval.defaultrequestvalidity=86400

# Default approval validity (how long an approved request should stay valid)
# Default : 28800 (8 Hours)
#approval.defaultapprovalvalidity=28800

# Setting excluding some classes from approval. When one of the classes in this list calls a method that normally 
# required approval, the call is immediately allowed, bypassing the approval mechanism. The list is comma separated.
# Uncomment the line below to exclude extra from approvals.
#approval.excludedClasses=org.ejbca.extra.caservice.ExtRACAServiceWorker
# Uncomment the line below to exclude CMP from approval.
#approval.excludedClasses=org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionBean
# Uncomment the line below to exclude revocation by CMP from approval.
#approval.excludedClasses=org.ejbca.core.protocol.cmp.RevocationMessageHandler
# Default : empty 
#approval.excludedClasses=

# ----------------- cluster configuration ----------------
# The configuration. Use "all" when clustering, 
# or for example "production" when deploying on JBoss EAP.
# Default: default
#jboss.config=all

# Name of the farm directory. Use "farm" when clustering.
# Default: deploy
#jboss.farm.name=farm

#------------------- EJBCA Healthcheck settings -------------
# Specifies the basic settings of the EJBCA Healthcheck servlet
# for more detailed configuration edit the file src/publicweb/healthcheck/WEB-INF/web.xml
# URL: http://localhost:8080/ejbca/publicweb/healthcheck/ejbcahealth
#
# Parameter specifying amount of free memory (Mb) before alarming
# Default: 1
#healthcheck.amountfreemem=1

# Parameter specifying database test query string. Used to check that
# the database is operational.
# Default : Select 1 From CertificateData where fingerprint='XX'
#healthcheck.dbquery=Select 1 From CertificateData where fingerprint='XX'

# Parameter specifying IP addresses authorized to access the healthcheck
# servlet. Use ';' for between multiple IPs.
# IPv6 address can be specified, for example 127.0.0.1;0:0:0:0:0:0:0:1. 
# "ANY" can be specified to allow any remote IP. 
# Default: 127.0.0.1 
#healthcheck.authorizedips=127.0.0.1

# Parameter to specify if the check of CA tokens should actually perform a signature test
# on the CA token, or it should only see if the token status is active.
# Default: false (don't perform a signature operation) 
#healthcheck.catokensigntest=false

# Parameter to specify if a connection test should be performed on each publisher.
# Default: true 
#healthcheck.publisherconnections=true

# Parameter to specify location of file containing information about maintenance
# Use this file to specify weather to include node in healthcheck or report as down for maintenance, 
# which will return an error message (either the property name specified below or a custom message specified in web.xml).
# Default: empty (not used)
#healthcheck.maintenancefile=~/maintenance.properties

# Parameter to configure name of maintenance property, default = DOWN_FOR_MAINTENANCE
# The healthcheck.maintenancefile should contain a single line like this:
# DOWN_FOR_MAINTENANCE=true
# Where the node will be down for maintenance of the property is true, and not down for maintenance if the property is false.
# Default: DOWN_FOR_MAINTENANCE
#healthcheck.maintenancepropertyname=DOWN_FOR_MAINTENANCE

# Text string used to say that every thing is ok with this node.
# Default=ALLOK
#healthcheck.okmessage=ALLOK
    
# Parameter saying if a errorcode 500 should be sent in case of error.
# Default=true
#healthcheck.sendservererror=true

# Uncomment this parameter if you want a static error message instead of one generated by the HealthChecker.
# Default=null
#healthcheck.customerrormessage=EJBCANOTOK

#------------------- CLI settings -------------
ejbca.cli.defaultusername=ejbca
ejbca.cli.defaultpassword=ejbca

#------------------- Debug and special settings -------------
#
# Custom Available Access Rules. Use ';' to separate multiple access rules
# Available values are the Access Rules strings in Advanced mode of 'Access Rules' in 'Administrator Roles'
# Default: ""
#ejbca.customavailableaccessrules=

# When upgrading a 100% up-time cluster, all nodes should be deployed with the effective version
# of the oldest still running EJBCA version.
# Default: \${app.version.number}
#app.version.effective=4.0.x

# To better protect from off-line brute force attacks of passwords on a compromised database, the
# computationally expensive BCrypt algorithm can be used. Using a higher log-rounds value will
# increase computational cost by log2. 1-31 can be used as BCrypt strength.
# 0 means simple SHA1 hashing will be used. A decent value for high security is ~8.
# Default=1
#ejbca.passwordlogrounds=1

# Parallel publishing invokes all the configured publishers for certificates in parallel instead of
# sequentially. So instead of waiting for the total time it takes to write to all publishers, you
# only have to wait for the time it takes to publish to the slowest one.
#
# This feature is non-compliant with the JEE5 specifications and could potentially have unintended
# side effects (even though none has been found so far).
# If you find any type of problem with this feature that can be mitigated by disabling it, please
# report it to the EJBCA developers or this option will disappear in a future version.
#
# Default: true
#publish.parallel.enabled=true

# ------------------- Peer Connector settings (Enterprise Edition only) -------------------
# These settings are never expected to be used and should be considered deprecated. If you do need
# to tweak this, please inform the EJBCA developers how and why this was necessary.
#
# Don't go through JCA for outgoing connections to peer systems. Applied at build time.
# Default: false
#peerconnector.rar.disabled=false
#
# Use TCP keep alive. Applied when connection pool is restarted. Default: true
#peerconnector.connection.sokeepalive=true
#
# Disable Nagle's algorithm. Applied when connection pool is restarted. Default: false
#peerconnector.connection.tcpnodelay=false
#
# Socket timeout in milliseconds. Applied when connection pool is restarted.
# Default: 20000 (default for Tomcat on the server side)
#peerconnector.connection.sotimeout=20000
#
# Connection pool size per peer connector. Applied when connection pool is restarted. Default: 100
#peerconnector.connection.maxpoolsize=100
#
# Background sync of certificate data. Batch size to compare. Default: 2000
#peerconnector.sync.batchsize=2000
#
# Background sync of certificate data. Number of entries to write in parallel. 1=sequential writes. Default: 12
#peerconnector.sync.concurrency=12
#
# Maximum allowed size for incoming messages. Default: 134217728 (128MiB)
#peerconnector.incoming.maxmessagesize=134217728
#
# How long a peer can be absent in milliseconds before (re-)authentication is triggered. Default: 60000
#peerconnector.incoming.authcachetime=60000
#
# How long to cache outgoing PeerData database objects.
# Default: 60000 (60 seconds)
# Possible values -1 (no caching) to 9223372036854775807 (2^63-1 = Long.MAX_VALUE).
#  If you want caching for an infinite time then set something high for example 157680000000 (5years).  
#peerconnector.cachetime=157680000000
#peerconnector.cachetime=-1
EOF



cat <<EOF > ejbca-custom/conf/install.properties
#
# \$Id$
#
# This is a sample file to override default properties used
# during installation of EJBCA (ant install)
# 
# You should copy and rename this file to install.properties
# and customize at will.
#

# ------------ Administrative CA configuration ---------------------
# This installation will create a first administrative CA. This CA will be used to create the first
# superadministrator and for the SSL server certificate of administrative web server.
# When the administrative web server have been setup you can create other CA:s and administrators.
# This is only used for administrative purposes,
# Enter a short name for the administrative CA.
ca.name=${ca_name}

# The Distinguished Name of the administrative CA. 
# This is used in the CA certificate to distinguish the CA.
# Note, you can not use DC components for the initial CA, you can create CAs 
# using DC components later on once the admin GUI is up and running.
ca.dn=${ca_dn}

# The token type the administrative CA will use.
# Use soft for software generated keys (default) or enter a class path for the HSM class.
# Normally the HSM class should be the PKCS11CryptoToken. 
#
# Possible values are:
# soft
# org.cesecore.keys.token.PKCS11CryptoToken
# se.primeKey.caToken.card.PrimeCAToken
# Note: If you use JBoss 7/EAP 6 and want to use PKCS#11 you have to configure JBoss to permit this. 
#       See instructions in the Install Guide.
#
# Default: soft
ca.tokentype=soft

# Password for the administrative CA token.
# With soft token, use password null.
# To prompt for the password on the terminal, don't set, i.e. comment out the line below.
# If no password should be used (for example nCipher module protected), use password '' (nothing).
ca.tokenpassword=null

# Configuration file were you define key name, password and key alias for the HSM used 
# by the administrative CA. Same as the Hard CA Token Properties in Admin gui.
# Remove everything in the file and add your own configuration.
# Note that this must be a full path.
# On windows use / instead of \
#ca.tokenproperties=${ejbca_home}/ejbca/conf/catoken.properties

# The keyspec for the administrative CAs key, to be generated in soft keystore.
# Keyspec for RSA keys is size of RSA keys (1024, 2048, 4096, 8192).
# Keyspec for ECDSA keys is name of curve or 'implicitlyCA', see docs.
ca.keyspec=2048

# The keytype for the administrative CA, can be RSA, ECDSA or DSA
# For the key to be generated in soft keystore.
ca.keytype=RSA

# Default signing algorithm for the administrative CA.
# Available algorithms are:
# SHA1WithRSA, SHA1withECDSA, SHA256WithRSA, SHA256withECDSA.
ca.signaturealgorithm=SHA256WithRSA

# The validity in days for the administrative CA, only digits.
ca.validity=3650

# The policy id of the administrative CA. Policy id determines which PKI policy the CA uses.
# Type your policy id or use '2.5.29.32.0' for 'any policy' (rfc5280) or 'null' for no policy at all.
ca.policy=null

# Certificate profile used for the CA certificate created during 'ant install'. 
# If you have a certificate profile imported you can use that. Otherwise default
# profile for ROOTCA is used.
# Default: ROOTCA
#ca.certificateprofile=MyOwnRootCACertificateProfile
EOF

cat <<EOF > ejbca-custom/conf/web.properties
# ------------ Web GUI configuration ---------------------
# When upgrading, the important options are:
# - httpsserver.password

# If you prefer to manually configure the web settings for your application
# server, you should uncomment this property. Enabling this option will prevent
# the 'ant web-configure' command from making any changes to the configuration
# of your application server (in terms of web settings, like paths etc).
# Can not be set to false, commented away means that web will be configured.
#web.noconfigure=true

# If you enable this option, the 'ant web-configure' command will not set-up the
# SSL access on your application server. This is normally desired for the OCSP
# responder or Validation Authority (unless you want to run them over https as
# well). Normally, in case of a CA build you should _not_ enable this option
# (otherwise you won't have access to the administration web interface). If you
# wish to use the Unid functionality on the OCSP responder, make sure to also
# have a look at the 'Configuring TLS on the Unid lookup server' how-to.
# Can not be set to false, commented away means that web will be configured.
# web.nosslconfigure=true

# Password for java trust keystore (p12/truststore.jks). Default is changeit
# This truststore will contain the CA-certificate after running 'ant javatruststore'
# Run 'ant -Dca.name=FooCA javatruststore' to install the CA-certificate for FooCA instead of the default ManagementCA
java.trustpassword=${truststorepass}

# The CN and DN of the super administrator.
# Comment out if you want 'ant install' to prompt for this.
superadmin.cn=${superadmin_cn}
# Note that superadmin.dn must start with the same CN as in superadmin.cn.
# example:  superadmin.dn=CN=\${superadmin.cn},${BASE_DN}
superadmin.dn=CN=\${superadmin.cn}

# The password used to protect the generated super administrator P12 keystore (to be imported in browser).
# Choose a good password here.
superadmin.password=${superadmin_password}

# Set this to false if you want to fetch the certificate from the EJBCA public web pages, instead of
# importing the P12-keystore. This can be used to put the initial superadmin-certificate on a smart card.
superadmin.batch=true

# The password used to protect the web servers SSL keystore. Default is serverpwd
# Choose a good password here.
# If upgrading from EJBCA 3.1, enter here the password found in 
#   \$JBOSS_HOME/server/default/deploy/jbossweb-tomcat55.sar/server.xml
#   under the section about 'HTTPS Connector...', the password is in attribute 'keystorePass=...'.
httpsserver.password=${httpsserver_password}

# The CA servers DNS host name, must exist on client using the admin GUI.
httpsserver.hostname=${httpsserver_hostname}

# The Distinguished Name of the SSL server certificate used by the administrative web gui.
# The CN part should match your host's DNS name to avoid browser warnings.
httpsserver.dn=CN=${httpsserver_hostname},${BASE_DN}

# The Alternative Name (certificate extension) of the SSL server certificate used by the administrative web gui.
# The dnsName part should match your hosts DNS name (and the CN above) to avoid browser warnings.
# Set automatically, so no need to change this property unless you want something exotic.
#httpsserver.an=dnsName=${httpsserver_hostname}

# The public port JBoss will listen to http on
# Default 8080
#httpserver.pubhttp=8080

# The public port JBoss will listen to https on, no client cert required
# Default 8442
#httpserver.pubhttps=8442

# The private port JBoss will listen to https on, client cert required
# Default 8443
#httpserver.privhttps=8443

# The private port exposed externally, i.e. if you run an Apache proxy in front of JBoss
# the port may be 443 instead.
# Default same as httpserver.privhttps
#httpserver.external.privhttps=443
 
# The fully qualified domain name (FQDN) of the front-end, e.g. an Apache proxy
#   In order to build absolute URL, the server name is got from the web client request.
#   But with an Apache proxy, via ProxyPass directive, the server name is 'localhost'.
# Use:
#   - empty: without Apache proxy, or with Apache proxy via AJP (not with ProxyPass)
#   - ${httpsserver_hostname}: when an Apache proxy is used on the same server than EJBCA
#   - any FQDN: when an Apache proxy with a ProxyPass directive is used (on any server)
# Default: (empty)
#httpserver.external.fqdn=
#httpserver.external.fqdn=${httpsserver_hostname}
 
# The interfaces JBoss will bind to. E.g. 127.0.0.1 will only allow connections from localhost.
# You can also specify \${jboss.bind.address} to use JBoss configuration which interface to listen on.
# Default 0.0.0.0
httpsserver.bindaddress.pubhttp=0.0.0.0
httpsserver.bindaddress.pubhttps=0.0.0.0
httpsserver.bindaddress.privhttps=0.0.0.0

# Defines the available languages by ISO 639-1 language codes separated with a comma (example: en,zh).
# If you are not sure that you know how to add a new language (languagefile.xx.properties, etc.), 
# we suggest you stick with the default the first time you install if you wan't to add your own language.
# Otherwise you may not be able to log in to the Admin GUI.
# Default: en,bs,de,es,fr,it,ja,pt,sv,uk,zh
#web.availablelanguages=en,bs,de,es,fr,it,ja,pt,sv,uk,zh

# Default content encoding used to display JSP pages, for example ISO-8859-1, UTF-8 or GBK.
# Default: UTF-8
web.contentencoding=UTF-8

# The language configuration that should be used internally for logging, exceptions and approval
# notifications has been moved to ejbca.properties from EJBCA 3.10.

# Show links to the EJBCA documentation. The links can either point to internally deployed
# documentation on the server or any exteral location like ejbca.org.
# Default = internal
#web.docbaseuri=disabled
web.docbaseuri=internal
#web.docbaseuri=http://www.ejbca.org

# Require administrator certificates to be available in database for revocation
# checks. Set this to false, if you want to be able to use admin certificates
# issued by external CAs.
# Default: true
#web.reqcertindb=true

# Allow users to self-register on public web, by entering their information.
# This creates an approval request for the admin.
# Default = false
web.selfreg.enabled=false

# Certificate types to make available for the user
#web.selfreg.defaultcerttype=1
#web.selfreg.certtypes.1.description=User certificate
#web.selfreg.certtypes.1.eeprofile=SOMEPROFILE
#web.selfreg.certtypes.1.certprofile=ENDUSER

# Optional: Instead of asking the user for a username, EJBCA can generate
# the username from a field in the subject DN
#web.selfreg.certtypes.1.usernamemapping=CN

# Deploy the request browser certificate renewal web application and show a 
# link to it from the EJBCA public web.
# Default = false
#web.renewalenabled=true

# Wether it should be possible to manually specify a custom class name in
# the admin web (e.g. for a custom Publisher or Service), or if the choice
# of class should be constrained to auto-detected classes only.
# If you are using classes made for EJBCA 5.0 or earlier you must enable
# this option, or wrap them in a "service" JAR file (see the Admin Guide).
# Default = false
#web.manualclasspathsenabled=true

# Presentation of the an exception on the web error page.
#
# General error message to be presented to the user when an exception occur.
# Default: An exception has occurred
#web.errorpage.notification=An exception has occurred.
#
# Print the stacktrace of the exception
# Default: true
#web.errorpage.stacktrace=false

# Custom Servlet filter for emulation of client certificate authentication to the Admin GUI
# using a Tomcat Valve or similar proxy.
# Default is false.
#web.enableproxiedauth=true

# Whether the remote IP address should be logged during administrator login.
# This works as expected when using an Apache AJP proxy, but if a reverse proxy
# server is running in front of EJBCA then the address of the proxy will be logged.
# In that case the web.log.adminforwardingip can be used in addition to this.
#
# If you want this information to be included in the webservice transaction log,
# you should add \${ADMIN_FORWARDED_IP} to the "ejbcaws.trx-log-order" property instead.
# 
# Default: true
web.log.adminremoteip=true

# Whether the IP address seen at the proxy (from the HTTP header "X-Forwarded-For")
# should be logged. This information can only be trusted if the request
# is known to come from a trusted proxy server.
#
# If you want this information to be included in the webservice transaction log,
# you should add \${ADMIN_FORWARDED_IP} to the "ejbcaws.trx-log-order" property instead.
#
# Default: false
#web.log.adminforwardedip=true

# Available PKCS#11 CryptoToken libraries and their display names
# If a library file's presence is not detected it will not show up in the Admin GUI.
# Default values (see src/java/defaultvalues.properties for most up to date values):
#cryptotoken.p11.lib.10.name=SafeNet ProtectServer Gold Emulator
#cryptotoken.p11.lib.10.file=/opt/ETcpsdk/lib/linux-x86_64/libctsw.so
#cryptotoken.p11.lib.11.name=SafeNet ProtectServer Gold
#cryptotoken.p11.lib.11.file=/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so
#cryptotoken.p11.lib.20.name=SafeNet Luna SA
#cryptotoken.p11.lib.20.file=/usr/lunasa/lib/libCryptoki2_64.so
#cryptotoken.p11.lib.21.name=SafeNet Luna PCI
#cryptotoken.p11.lib.21.file=/usr/lunapci/lib/libCryptoki2_64.so
#cryptotoken.p11.lib.22.name=SafeNet Luna PCI
#cryptotoken.p11.lib.22.file=/Program Files/LunaPCI/cryptoki.dll
#cryptotoken.p11.lib.23.name=SafeNet Luna Client
#cryptotoken.p11.lib.23.file=/usr/safenet/lunaclient/lib/libCryptoki2_64.so
#cryptotoken.p11.lib.30.name=Utimaco
#cryptotoken.p11.lib.30.file=/opt/utimaco/p11/libcs2_pkcs11.so
#cryptotoken.p11.lib.31.name=Utimaco
#cryptotoken.p11.lib.31.file=/opt/Utimaco/Software/PKCS11/lib/Linux-x86-64/libcs2_pkcs11.so
#cryptotoken.p11.lib.32.name=Utimaco
#cryptotoken.p11.lib.32.file=/etc/utimaco/libcs2_pkcs11.so
#cryptotoken.p11.lib.33.name=Utimaco
#cryptotoken.p11.lib.33.file=C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll
#cryptotoken.p11.lib.40.name=Thales
#cryptotoken.p11.lib.40.file=/opt/nfast/toolkits/pkcs11/libcknfast.so
#cryptotoken.p11.lib.50.name=ARX CoSign
#cryptotoken.p11.lib.50.file=C:/windows/system32/sadaptor.dll
#cryptotoken.p11.lib.60.name=OpenSC
#cryptotoken.p11.lib.60.file=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
#cryptotoken.p11.lib.61.name=OpenSC
#cryptotoken.p11.lib.61.file=/usr/lib/i386-linux-gnu/opensc-pkcs11.so
#cryptotoken.p11.lib.62.name=OpenSC
#cryptotoken.p11.lib.62.file=/usr/local/lib/opensc-pkcs11.so
#cryptotoken.p11.lib.63.name=OpenSC
#cryptotoken.p11.lib.63.file=C:/Windows/system32/opensc-pkcs11.dll
#cryptotoken.p11.lib.64.name=OpenSC
#cryptotoken.p11.lib.64.file=/usr/lib64/pkcs11/opensc-pkcs11.so
#cryptotoken.p11.lib.70.name=Bull TrustWay CryptoBox
#cryptotoken.p11.lib.70.file=/usr/lib64/libcryptobox_clnt.so
#cryptotoken.p11.lib.71.name=Bull TrustWay PCI Crypto Card
#cryptotoken.p11.lib.71.file=/usr/lib64/libgpkcs11cc2000.so
#cryptotoken.p11.lib.72.name=Bull TrustWay Proteccio
#cryptotoken.p11.lib.72.file=/usr/lib64/libnethsm64.so
#cryptotoken.p11.lib.80.name=SoftHSM 2
#cryptotoken.p11.lib.80.file=/usr/local/lib/softhsm/libsofthsm2.so
#cryptotoken.p11.lib.81.name=SoftHSM 2
#cryptotoken.p11.lib.81.file=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
#cryptotoken.p11.lib.82.name=SoftHSM 2
#cryptotoken.p11.lib.82.file=/usr/lib/softhsm/libsofthsm2.so
#cryptotoken.p11.lib.83.name=SoftHSM 2
#cryptotoken.p11.lib.83.file=/usr/lib64/pkcs11/libsofthsm2.so
#cryptotoken.p11.lib.90.name=SoftHSM
#cryptotoken.p11.lib.90.file=/usr/lib/softhsm/libsofthsm.so
#cryptotoken.p11.lib.91.name=SoftHSM
#cryptotoken.p11.lib.91.file=/usr/lib64/softhsm/libsofthsm.so
#cryptotoken.p11.lib.100.name=PKCS11 Spy
#cryptotoken.p11.lib.100.file=/usr/lib/x86_64-linux-gnu/pkcs11-spy.so
#cryptotoken.p11.lib.101.name=PKCS11 Spy
#cryptotoken.p11.lib.101.file=/usr/lib64/pkcs11/pkcs11-spy.so
#cryptotoken.p11.lib.110.name=Utimaco R2
#cryptotoken.p11.lib.110.file=/opt/utimaco/p11/libcs_pkcs11_R2.so
#cryptotoken.p11.lib.111.name=Utimaco R2
#cryptotoken.p11.lib.111.file=/opt/Utimaco/Linux/x86_64/Crypto_APIs/PKCS11_R2/lib/libcs_pkcs11_R2.so
#cryptotoken.p11.lib.112.name=Utimaco R2
#cryptotoken.p11.lib.112.file=/etc/utimaco/libcs_pkcs11_R2.so
#
# You can add your own values with an available number, or override numbers from defaults...
#cryptotoken.p11.lib.255.name=P11 Proxy
#cryptotoken.p11.lib.255.file=/home/user/local/p11proxy/dist/p11proxy.so
#
# If you would like to restrict the accessible slots, you can use the following property:
# (you can use ranges, and if you omit the low or high number it means "no limit")
#cryptotoken.p11.lib.30.slotlist=1-100
#cryptotoken.p11.lib.30.slotlist=0,1,65537
#cryptotoken.p11.lib.30.slotlist=i1-i
# To change the default slot (e.g. if you have disabled access to slot 0)
#cryptotoken.p11.defaultslot=1
#cryptotoken.p11.defaultslot=i1

# Available PKCS#11 CryptoToken attribute files and their display names
# Use if the default PKCS#11 attributes are not good for the PKCS#11 module and if needs specific attributes 
#cryptotoken.p11.attr.0.name=
#cryptotoken.p11.attr.0.file=
#...
#cryptotoken.p11.attr.255.name=
#cryptotoken.p11.attr.255.file=
EOF
}


cat <<EOF
#######        #  ######    #####      #     
#              #  #     #  #     #    # #    
#              #  #     #  #         #   #   
#####          #  ######   #        #     #  
#        #     #  #     #  #        #######  
#        #     #  #     #  #     #  #     #  
#######   #####   ######    #####   #     #  

This installs the EJBCA PKI
EOF

cd $INSTALL_DIRECTORY
if [ $EUID -eq 0 ]; then
  echo "Do not execute this script as root"
  echo "We did nothing yet"
  exit 1
fi


cd $INSTALL_DIRECTORY
if [ -d ejbca-custom ]; then
  echo "$INSTALL_DIRECTORY/ejbca-custom already exists"
  echo "we will do nothing here"
  echo "remove the ejbca-custom directory to re-install from scratch"
  exit 0
fi


PKG_INSTALL=""
if [ -f /etc/redhat-release ]; then
  echo "found RedHat/CentOS"
  PKG_INSTALL="yum install tar unzip java-1.8.0-openjdk-devel ant psmisc mariadb bc patch"
  BASE_OS=RHEL
else if [ -f /etc/debian_version ]; then
  echo "found Debian/Ubuntu"
  PKG_INSTALL="apt install unzip openjdk-8-jdk-headless ant ant-optional psmisc mariadb-client bc patch"
  BASE_OS=UBUNTU
  else
    echo "Unknown platform, your milage may vary"
  fi
fi

#RUN_AS_ROOT_FILE="/tmp/run_as_root.sh"
#cat <<EOF >${RUN_AS_ROOT_FILE}
#$PKG_INSTALL

#cat <<EOF2 > /etc/systemd/system/ejbca.service
#[Unit]
#Description=EJBCA PKI
#After=network.target

#[Service]
#Type=simple
#User=${ejbca_user}
#Group=${ejbca_group}
#WorkingDirectory=${ejbca_home}
#ExecStart=${ejbca_home}/wildfly/bin/standalone.sh -b 0.0.0.0
#ExecStop=${ejbca_home}/wildfly/bin/jboss-cli.sh --connect command=:shutdown
#Restart=on-failure
#RestartSec=300s

#[Install]
#WantedBy=multi-user.target
#EOF2

#systemctl daemon-reload

#rm -f "${RUN_AS_ROOT_FILE}"
#EOF
#chmod 755 "${RUN_AS_ROOT_FILE}"

echo "EJBCA will be installed as OS user '${ejbca_user}'"
echo 
echo "please install dependencies with:"
echo $PKG_INSTALL
#echo "please execute /tmp/run_as_root.sh as root (installs needed packages and creates a systemctl service for ejbca)"
echo
echo "Please select \"Yes\" if you did so, but not before"
select yn in "Yes" "No"; do
  case $yn in
    Yes )
    init_installer;
    echo;
    echo "You can now install the superadmin.p12 keystore, from ${EJBCA_DIRECTORY}/p12, in your web browser, using the password ${superadmin_password}, and access EJBCA at https://localhost:8443/ejbca";
    echo;
  break;;
  No ) exit;;
  esac
done
