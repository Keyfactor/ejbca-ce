#!/bin/bash

# Check if the environment variable is set
if [ -z "$EJBCA_HOME" ];
then
  echo "Error: Environment variable EJBCA_HOME is not set."
  exit 1
fi

pushd "$EJBCA_HOME" || exit
ant clean build -Dejbca.plugin.conf.path="$EJBCA_HOME"/src/samples/plugins | tee output.log
grep 'Plugin Builder Tester Executing!' output.log
export result=$?
rm output.log
popd || exit

if [ $result -eq 0 ];
then
  printf "\n%s\n" "SUCCESS: Sample plugins were built successfully"
else
  printf "\n%s\n" "FAILURE: line 'Plugin Builder Tester Executing!' from the build script is missing."
  exit 1
fi

