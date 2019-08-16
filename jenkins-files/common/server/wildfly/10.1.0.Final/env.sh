#!/usr/bin/env bash

# JBoss
JBOSS_HOME=/opt/jboss/wildfly
JBOSS_BIN=$JBOSS_HOME/bin
JBOSS_CLI=$JBOSS_HOME/bin/jboss-cli.sh
JBOSS_STANDALONE=$JBOSS_HOME/standalone
JBOSS_STANDALONE_CONF=$JBOSS_STANDALONE/configuration
JBOSS_STANDALONE_DEPLOYMENTS=$JBOSS_STANDALONE/deployments

export JBOSS_HOME="${JBOSS_HOME}"
export JBOSS_BIN="${JBOSS_BIN}"
export JBOSS_CLI="${JBOSS_CLI}"
export JBOSS_STANDALONE="${JBOSS_STANDALONE}"
export JBOSS_STANDALONE_CONF="${JBOSS_STANDALONE_CONF}"
export JBOSS_STANDALONE_DEPLOYMENTS=${JBOSS_STANDALONE_DEPLOYMENTS}

wait_for_server() {
    SERVER_STARTED=0
    # Wait for up to 180 seconds for server to start up
    for i in {1..90} ; do
        SERVER_RUNNING=`JAVA_OPTS="$JBOSSCLI_OPTS" $JBOSS_CLI -c --command=":read-attribute(name=server-state)" | grep running`
        echo "SERVER_RUNNING [${SERVER_RUNNING}]"
        if [ ! -z "$SERVER_RUNNING" ]
        then
            echo "Server started."
            SERVER_STARTED=1
            break
        fi
		echo "waiting for server [${i}]..."
        echo
		sleep 2
	done
	if [ "$SERVER_STARTED" -ne 1 ]; then
		echo "WildFly server start timed out."
		exit 1;
	fi
}

export -f wait_for_server

wait_for_deployment() {
	DEPLOY_SUCCESSFUL=0
	# Wait for up to 180 seconds for app to start up
	for i in {1..90} ; do
		if [ -e "$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.deployed" ] ; then
			echo "EJBCA successfully started."
			DEPLOY_SUCCESSFUL=1
			break
		fi
		if [ -e "$JBOSS_STANDALONE_DEPLOYMENTS/ejbca.ear.failed" ] ; then
			echo "EJBCA deploy failed."
			exit 1;
		fi
		echo "waiting for deployment [${i}]..."
        echo
		sleep 2
	done
	if [ "$DEPLOY_SUCCESSFUL" -ne 1 ]; then
		echo "EJBCA deploy timed out."
		exit 1;
	fi
}

export -f wait_for_deployment

# Options for Main JVM
export TEST_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx512m"
# Options for ant itself. The report building can be memory heavy, otherwise it shouldn't need much memory
export ANT_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -XX:OnOutOfMemoryError='kill -9 %p' -Xms64m -Xmx768m"
# Options for the CLI tools. These require very little memory.
# Note that the Wildfly CLI does not do escaping properly, so we can't use option values with spaces.
export JBOSSCLI_OPTS="-XX:+UseG1GC -XX:+UseCompressedOops -Xms32m -Xmx128m"