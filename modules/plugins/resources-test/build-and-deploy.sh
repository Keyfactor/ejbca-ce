#!/bin/bash

#rm -rf *.ear
#source build-plugin-from-pre-compiled-jar.sh
#cp $EJBCA_HOME/dist/ejbca.ear ejbca-plugin-from-pre-compiled-jar.ear

#source build-plugin-from-source.sh
#cp $EJBCA_HOME/dist/ejbca.ear ejbca-plugin-from-source.ear

#source build-plugin-without-parameters.sh
#cp $EJBCA_HOME/dist/ejbca.ear ejbca-plugin-without-parameters.ear

do_shutdown_wildfly_if_running() {
  export wildfly_pid=$(sudo lsof -i :$1|sed 's/java\s*//g'|sed 's/\s.*//g'|grep -iv command)
  if [ -n "$wildfly_pid" ];
  then
    echo "# Stopping WildFly"
    sudo kill $wildfly_pid
    sleep 5s
  fi
}

shutdown_wildfly_if_running() {
  do_shutdown_wildfly_if_running 8080
  do_shutdown_wildfly_if_running 9990
}

shutdown_wildfly_if_running

test_plugin() {
  export version=$1
  export current_dir=$(pwd)
  pushd /opt/wildfly-${version}/bin
  ./standalone.sh 2>&1 1>$current_dir/wildfly-${version}.log &
  popd
  sleep 5
  cp *.ear /opt/wildfly-${version}/standalone/deployments/
  sleep 30

  shutdown_wildfly_if_running
}

#test_plugin 24.0.1.Final
test_plugin 26.1.3.Final
#test_plugin 32.0.0.Final
