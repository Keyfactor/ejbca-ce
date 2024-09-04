#!/bin/bash

# Check if the environment variable is set
if [ -z "$EJBCA_HOME" ];
then
  echo "Error: Environment variable EJBCA_HOME is not set."
  exit 1
fi

pushd $EJBCA_HOME
ant clean build -Dejbca.plugin.conf.path=$EJBCA_HOME/src/samples/plugins
popd
