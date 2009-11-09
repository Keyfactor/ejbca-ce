#!/bin/sh

java -Djava.endorsed.dirs=lib/endorsed -cp ejbca-ws-cli.jar org.ejbca.core.protocol.ws.client.cvcwscli "$@"
