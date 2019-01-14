FROM selenium/standalone-firefox-debug:3.141.59-dubnium

USER root

#Create Ant Dir
RUN mkdir -p /opt/ant/

#Create Appserver Home Dir (dummy, but needed for WebTests suite)
RUN mkdir -p /opt/jboss/wildfly

# environment variables
ENV ANT_HOME /opt/ant/apache-ant-1.9.8
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"
ENV ANT_OPTS="-Xms256M -Xmx512M"
# ENV APPSRV_HOME ="/opt/jboss/wildfly/"

RUN cd $HOME \
	&& curl -O http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.8-bin.tar.gz \
    && tar xf apache-ant-1.9.8-bin.tar.gz \
    && mv $HOME/apache-ant-1.9.8 $ANT_HOME \
    && rm apache-ant-1.9.8-bin.tar.gz \
    && chmod -R g+rw ${ANT_HOME}

# install JDK instead of JRE
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk

# Set the working directory to EJBCA rource root folder
WORKDIR /app/ejbca

ADD run.sh /opt/
RUN chmod +x /opt/run.sh

ADD configuration/firefox_conf/svq3ko35.default /home/seluser/.mozilla/firefox/svq3ko35.default
RUN chmod -R 777 /home/seluser/.mozilla/firefox/svq3ko35.default

ADD configuration/firefox_conf/profiles.ini /home/seluser/.mozilla/firefox/profiles.ini
RUN chmod 777 /home/seluser/.mozilla/firefox/profiles.ini

# copy ejbca conf to /opt in the container for runtime-usage
ADD configuration/ejbca_conf /opt/ejbca_conf
RUN chmod 777 /opt/ejbca_conf

# copy ejbca-webtest module conf to /opt in the container for runtime-usage
ADD configuration/ejbca_webtest_conf /opt/ejbca_webtest_conf
RUN chmod 777 /opt/ejbca_webtest_conf

# need to run as root, because source checkout user is not accessible to seluser and is not allwed to chmod by jenkinsuser ?
# need to run as seluser, because firefox needs to be run as seluser for the profile to work properly inside the container ?
USER seluser

CMD ["/opt/run.sh"]
