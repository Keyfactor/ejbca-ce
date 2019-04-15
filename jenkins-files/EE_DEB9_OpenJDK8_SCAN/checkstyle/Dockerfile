FROM debian:stretch

USER 0

RUN \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update && \
    apt-get -qq -y upgrade && \
    apt-get -qq -y install --no-install-recommends openjdk-8-jdk-headless wget unzip > /dev/null && \
    apt-get -qq autoclean #&& rm -rf /var/lib/apt/lists/*

RUN \
    wget -q https://github.com/checkstyle/checkstyle/releases/download/checkstyle-8.19/checkstyle-8.19-all.jar -O checkstyle-8.19-all.jar && \
    sha256sum checkstyle-8.19-all.jar | grep d35bd180c22a8304be1c8e7ab44832300bda14da1bb70a1c29f8c5946424fd80 && \
    mv checkstyle-8.19-all.jar /opt/checkstyle.jar && \
    chgrp -R 0   /opt/checkstyle.jar && \
    chmod -R g=u /opt/checkstyle.jar

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
CMD ["/opt/imports/bin/run-checkstyle.sh"]
