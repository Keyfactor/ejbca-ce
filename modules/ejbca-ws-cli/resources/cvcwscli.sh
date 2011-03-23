#!/bin/sh

java -Djava.endorsed.dirs=lib/endorsed -cp `dirname "$0"`/ejbca-ws-cli.jar org.ejbca.core.protocol.ws.client.cvcwscli "$@"
