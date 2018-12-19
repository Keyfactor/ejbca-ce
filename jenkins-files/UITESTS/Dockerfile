FROM selenium/standalone-firefox-debug:3.141.59-dubnium

user root

#Create Ant Dir
RUN mkdir -p /opt/ant/

#Setting Ant Home
ENV ANT_HOME /opt/ant/apache-ant-1.9.8

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

user seluser

CMD ["/opt/run.sh"]
