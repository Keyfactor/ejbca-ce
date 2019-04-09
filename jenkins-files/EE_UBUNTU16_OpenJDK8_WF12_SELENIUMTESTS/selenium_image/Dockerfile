FROM selenium/standalone-firefox-debug:3.141.59-dubnium

USER root

#Create Ant Dir
RUN mkdir -p /opt/ant/

#Create Appserver Home Dir (dummy, but needed for WebTests suite)
RUN mkdir -p /opt/jboss/wildfly

# environment variables
ENV ANT_HOME /opt/ant/apache-ant-1.9.8
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"
ENV ANT_OPTS="-Xms1024M -Xmx1024M"
ENV JAVA_OPTS="-Xms2048m -Xmx2048m -XX:MetaspaceSize=192M -XX:MaxMetaspaceSize=256m -XX:PermSize=1024m -XX:MaxPermSize=512m -Djava.net.preferIPv4Stack=true"
ENV EJBCA_HOME="/app/ejbca"

RUN cd $HOME \
	&& curl -O http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.8-bin.tar.gz \
    && tar xf apache-ant-1.9.8-bin.tar.gz \
    && mv $HOME/apache-ant-1.9.8 $ANT_HOME \
    && rm apache-ant-1.9.8-bin.tar.gz \
    && chmod -R g+rw ${ANT_HOME}

# install JDK instead of JRE
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk
RUN apt-get install -y libnss3-tools

# Set the working directory to EJBCA rource root folder
WORKDIR /app/ejbca

ADD run.sh /opt/
RUN chmod +x /opt/run.sh

ADD configuration/firefox_conf/svq3ko35.default /home/jenkins/.mozilla/firefox/svq3ko35.default
RUN chown -R 1001:1001 /home/jenkins/.mozilla/firefox/svq3ko35.default

ADD configuration/firefox_conf/profiles.ini /home/jenkins/.mozilla/firefox/profiles.ini
RUN chown -R 1001:1001 /home/jenkins/.mozilla/firefox/profiles.ini

# copy ejbca conf to /opt in the container for runtime-usage
ADD configuration/ejbca_conf /opt/ejbca_conf
RUN chown -R 1001:1001 /opt/ejbca_conf

# copy ejbca-webtest module conf to /opt in the container for runtime-usage
ADD configuration/ejbca_webtest_conf /opt/ejbca_webtest_conf
RUN chown -R 1001:1001 /opt/ejbca_webtest_conf

# copy jboss-ejb-client.properties to /opt in the container for runtime-usage
ADD configuration/jboss-ejb-client.properties /opt/
RUN chown -R 1001:1001 /opt/jboss-ejb-client.properties

# the docker image uses 'seluser' (UID 1000) for running Selenium, but we want to use the 'jenkins' user (UID 1001), so it matches the host.
# copy VNC settings from 'seluser' to 'jenkins' user
RUN cp -a /home/seluser/.vnc /home/jenkins/.vlc
RUN chown -R 1001:1001 /home/jenkins/.vlc

# Create jenkins user & group and make sure everything is owned by this user
RUN userdel default || true
RUN groupadd -g 1001 jenkins
RUN useradd -d /home/jenkins -g jenkins -m -u 1001 jenkins
RUN chown -R jenkins:jenkins /opt/jboss

ENV HOME /home/jenkins
USER jenkins:jenkins

CMD ["/opt/run.sh"]
