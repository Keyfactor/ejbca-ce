#!/bin/bash

set -e

rm -rf "wildfly.log"

run_cmd() {
  echo "\$ $1"
  eval $1
}

show() {
  echo "$1"
}

do_shutdown_wildfly_if_running() {
  export wildfly_pid=$(sudo lsof -i :$1|sed 's/java\s*//g'|sed 's/\s.*//g'|grep -iv command)
  if [ -n "$wildfly_pid" ];
  then
    show "# Stopping WildFly"
    run_cmd "sudo kill $wildfly_pid"
    sleep 5s
  fi
}

shutdown_wildfly_if_running() {
  do_shutdown_wildfly_if_running 8080
  do_shutdown_wildfly_if_running 9990
}

OPTSTRING=":d:i:u:v:"

# Some default options
db="mariadb"
install_dir="/opt"
wildflyuser=$(whoami)
version="32.0.0.Final"

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
    v)
      version=${OPTARG}
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
show "# WildFly version        : ${version}"
run_cmd "mkdir -p ${install_dir}"

if [ -d ${install_dir}/wildfly-${version} ];
then
  echo ""
  echo "WildFly $version is already installed."
  echo "Remove it manually if you would like to install it again."
  exit 1
fi

shutdown_wildfly_if_running

if [ "$version" = "24.0.1.Final" ];
then
  source do_install_24_0_1.sh
elif [ "$version" = "26.1.3.Final" ];
then
  source do_install_26_1_3.sh
elif [ "$version" = "32.0.0.Final" ];
then
  source do_install_32_0_0.sh
else
  echo "$version is an unknown WildFly version. Valid versions are:"
  echo "Valid versions are:"
  echo "   24.0.1.Final"
  echo "   26.1.3.Final"
  echo "   32.0.0.Final"
  exit 1
fi

shutdown_wildfly_if_running

echo ""
echo "Installation succeeded"
