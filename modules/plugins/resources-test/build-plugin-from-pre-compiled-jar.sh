#!/bin/bash

# Check if the environment variable is set
if [ -z "$EJBCA_HOME" ];
then
  echo "Error: Environment variable EJBCA_HOME is not set."
  exit 1
fi

pushd $EJBCA_HOME

rm -rf /tmp/plugin
mkdir /tmp/plugin

# copy some lib that's usually not included in ejbca.ear to the plugin dir
cp lib/ext/test/easymock*.jar /tmp/plugin/

# create a properties file for the external JAR plugin
echo "plugin.ejbca.lib.dir=/tmp/plugin/" > conf/plugins/test-jar-plugin.properties

# build
ant clean build

popd
