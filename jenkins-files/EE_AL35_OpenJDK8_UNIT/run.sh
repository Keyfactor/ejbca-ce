#!/bin/sh

cp /opt/conf/* /app/ejbca/conf/

ant clean build
