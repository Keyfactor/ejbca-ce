#!/bin/sh

java -Djava.endorsed.dirs=lib -cp ejbcawscli.jar org.ejbca.core.protocol.ws.client.cvcwscli "$@"
