#!/bin/bash

# Check if the environment variable is set
if [ -z "$EJBCA_HOME" ];
then
  echo "Error: Environment variable EJBCA_HOME is not set."
  exit 1
fi

pushd $EJBCA_HOME
ant clean build -Dejbca.plugin.conf.path=$EJBCA_HOME/src/samples/plugins | tee output.log
grep 'Plugin Builder Tester Executing!' output.log
export result=$?
rm -rf output.log
popd

echo ""
echo ""
echo ""

if [ $result -eq 0 ];
then
  echo "Plugin built successfully"
  echo ""
else
  echo "The line: 'Plugin Builder Tester Executing!' from the build script is missing."
  echo ""
  exit 1
fi

