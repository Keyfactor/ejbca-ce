#!/bin/bash

# Check if the environment variable is set
if [ -z "$EJBCA_HOME" ];
then
  echo "Error: Environment variable EJBCA_HOME is not set."
  exit 1
fi

pushd "$EJBCA_HOME" || exit

rm -rf /tmp/plugin
mkdir /tmp/plugin

# copy some lib that's usually not included in ejbca.ear to the plugin dir
cp lib/ext/test/easymock*.jar /tmp/plugin/

# create a properties file for the external JAR plugin
rm conf/plugins/test-jar-plugin.properties
echo "plugin.ejbca.lib.dir=/tmp/plugin/" > conf/plugins/test-jar-plugin.properties

# build
ant clean build

# clean up
rm conf/plugins/test-jar-plugin.properties
rm -rf /tmp/plugin

# Verify that the easymock jar is included in the .ear-file
if unzip -l dist/ejbca.ear | grep easymock
then
  printf "\n%s\n" "SUCCESS: The plugin is included in ejbca.ear"
else
  printf "\n%s\n" "FAILURE: The plugin is NOT included in ejbca.ear"
  exit 1
fi

popd
