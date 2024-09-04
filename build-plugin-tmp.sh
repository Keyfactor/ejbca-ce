#!/bin/bash
set -e

echo "*"
echo "* Building without any parameters"
echo "*"
ant clean build

rm -rf dist/tmp
mkdir -p dist/tmp
unzip -q dist/ejbca.ear -d dist/tmp
find dist/tmp/lib/|grep easymock
if [ ! $? -eq 0 ];
then
    echo "File not found!"
    exit 1
fi
if [ ! -f dist/tmp/lib/ ]; then
    echo "File not found!"
fi


echo "*"
echo "* Build plugin from source"
echo "*"
ant clean build -Dejbca.plugin.conf.path=$EJBCA_HOME/src/samples/plugins

echo "*"
echo "* Build plugin from pre-compiled jar"
echo "*"

rm -rf /tmp/plugin
mkdir /tmp/plugin

# copy some lib that's usually not included in ejbca.ear to the plugin dir
cp lib/ext/test/easymock-5.2.0.jar /tmp/plugin/

# create a properties file for the external JAR plugin
echo "plugin.ejbca.lib.dir=/tmp/plugin/" > conf/plugins/test-jar-plugin.properties

# build
ant clean build

# cleanup
rm conf/plugins/test-jar-plugin.properties

# observe the error in the console output

# open ejbca.ear and see that easymock-5.2.0.jar was still included and is present under the lib/ directory
rm -rf dist/tmp
mkdir -p dist/tmp
unzip dist/ejbca.ear -d dist/tmp
find dist/tmp/lib/|grep easymock
if [ $? -ne 0 ];
then
    echo "File not found!"
    exit 1
fi
if [ ! -f dist/tmp/lib/ ]; then
    echo "File not found!"
fi

