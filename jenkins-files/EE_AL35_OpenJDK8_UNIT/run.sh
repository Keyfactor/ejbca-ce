#!/bin/sh

whoami

cp /opt/conf/* /app/ejbca/conf/

ant clean build test:runsa
