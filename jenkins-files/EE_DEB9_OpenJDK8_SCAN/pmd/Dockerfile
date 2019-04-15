FROM debian:stretch

USER 0

RUN \
    export DEBIAN_FRONTEND=noninteractive ; \
    apt-get update && \
    apt-get -qq -y upgrade && \
    apt-get -qq -y install --no-install-recommends openjdk-8-jdk-headless wget unzip > /dev/null && \
    apt-get -qq autoclean #&& rm -rf /var/lib/apt/lists/*

RUN \
    wget -q https://github.com/pmd/pmd/releases/download/pmd_releases%2F6.13.0/pmd-bin-6.13.0.zip -O pmd-bin-6.13.0.zip && \
    sha256sum pmd-bin-6.13.0.zip | grep 2ccb17a3b9845679e310a68a7f1d328feabc12668e774b0496e0f8ef0ab8df7d && \
    unzip pmd-bin-6.13.0.zip && \
    mv pmd-bin-6.13.0 /opt/pmd  && \
    chmod +x     /opt/pmd/bin/*.sh && \
    chgrp -R 0   /opt/pmd && \
    chmod -R g=u /opt/pmd

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
CMD ["/opt/imports/bin/run-pmd.sh"]
