#!/bin/sh

java -Djava.endorsed.dirs=lib/endorsed -jar `dirname "$0"`/xkmscli.jar "$@"