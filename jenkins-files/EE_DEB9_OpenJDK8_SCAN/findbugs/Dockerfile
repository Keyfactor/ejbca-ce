FROM debian:stretch

USER 0

RUN \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update && \
    apt-get -qq -y upgrade && \
    apt-get -qq -y install --no-install-recommends openjdk-8-jdk-headless ant ant-optional libfindbugs-java > /dev/null && \
    apt-get -qq autoclean #&& rm -rf /var/lib/apt/lists/*

ADD imports/ /opt/imports/

RUN \
    chmod +x     /opt/imports/bin/*.sh && \
    mkdir                     /home/jenkins && \
    chgrp -R 0   /opt/imports /home/jenkins /etc/passwd && \
    chmod -R g=u /opt/imports /home/jenkins /etc/passwd

# This directory is expected to be mounted using -v /path:/home/jenkins
WORKDIR /home/jenkins

ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64

# Is is expected that the container is run using the current unprivileged user allowed access to root group files "-u $(id -u) --group-add root"
USER 10001

# Container will not be started with this command when from from Jenkins
CMD ["/opt/imports/bin/run-findbugs.sh"]
