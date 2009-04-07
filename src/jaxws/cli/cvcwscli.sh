#!/bin/sh

java -Djava.endorsed.dirs=lib/endorsed -cp ejbcawscli.jar org.ejbca.core.protocol.ws.client.cvcwscli "$@"
