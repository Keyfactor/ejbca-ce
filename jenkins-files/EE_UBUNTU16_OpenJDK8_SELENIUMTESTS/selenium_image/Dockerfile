FROM selenium/standalone-firefox-debug:3.141.59-dubnium

USER root

#Create Ant Dir
RUN mkdir -p /opt/ant/


#Updating Path
ENV ANT_HOME /opt/ant/apache-ant-1.9.8
ENV ANT_OPTS="-Xms256M -Xmx512M"
ENV APPSRV_HOME ="/opt/jboss/wildfly/"

RUN cd $HOME \
	&& curl -O http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.8-bin.tar.gz \
    && tar xf apache-ant-1.9.8-bin.tar.gz \
    && mv $HOME/apache-ant-1.9.8 $ANT_HOME \
    && rm apache-ant-1.9.8-bin.tar.gz \
    && chmod -R g+rw ${ANT_HOME}

#Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"

# install JDK instead of JRE
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk

# Set the working directory to EJBCA rource root folder
WORKDIR /app/ejbca

ADD run.sh /opt/
RUN chmod +x /opt/run.sh

ADD configuration/firefox_conf/svq3ko35.default /home/seluser/.mozilla/firefox/svq3ko35.default
RUN chmod 777 /home/seluser/.mozilla/firefox/svq3ko35.default

ADD configuration/firefox_conf/profiles.ini /home/seluser/.mozilla/firefox/profiles.ini
RUN chmod 777 /home/seluser/.mozilla/firefox/profiles.ini

# copy ejbca conf to /opt in the container for runtime-usage
ADD configuration/ejbca_conf /opt/ejbca_conf
RUN chmod 777 /opt/ejbca_conf

# copy ejbca-webtest module conf to /opt in the container for runtime-usage
ADD configuration/ejbca_webtest_conf /opt/ejbca_webtest_conf
RUN chmod 777 /opt/ejbca_webtest_conf

# USER seluser

CMD ["/opt/run.sh"]
