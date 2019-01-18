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

# copy jboss-ejb-client.properties to /opt in the container for runtime-usage
ADD configuration/jboss-ejb-client.properties /opt/
RUN chmod 777 /opt/jboss-ejb-client.properties

# copy jboss-ejb-client.properties to /opt in the container for runtime-usage
ADD configuration/propertyDefaults.xml /opt/
RUN chmod 777 /opt/propertyDefaults.xml

# need to run as seluser, because firefox needs to be run as seluser for the profile to work properly inside the container
USER seluser

CMD ["/opt/run.sh"]
