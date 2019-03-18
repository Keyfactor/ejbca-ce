FROM jboss/wildfly:12.0.0.Final

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
    && chown -R jboss:0 ${ANT_HOME} \
    && chmod -R g+rw ${ANT_HOME}

#Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"
ENV JAVA_OPTS="-XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -Xms2048m -Xmx2048m -XX:MetaspaceSize=192M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true"
ENV ANT_OPTS="-Xms256M -Xmx512M"
ENV APPSRV_HOME ="/opt/jboss/wildfly/"

RUN yum install -y which

# copy WildFly conf
ADD standalone.xml /opt/jboss/wildfly/standalone/configuration/standalone.xml
ADD application-roles.properties /opt/jboss/wildfly/standalone/configuration/application-roles.properties
ADD application-users.properties /opt/jboss/wildfly/standalone/configuration/application-users.properties

# copy keystore file to WildFly
#ADD keystore /opt/jboss/wildfly/standalone/configuration/keystore

# add mariadb driver to deploy folder
ADD mariadb-java-client.jar /opt/jboss/wildfly/standalone/deployments/mariadb-java-client.jar


# Set the working directory to EJBCA rource root folder
WORKDIR /app/ejbca

# copy p12 folder to /opt in the container for runtime-usage
ADD p12 /opt/p12
RUN chmod 777 /opt/p12

# copy ejbca conf to /opt in the container for runtime-usage
ADD conf /opt/conf
RUN chmod 777 /opt/conf

# copy ManagementCA.pem to /opt in the container for runtime-usage
ADD ManagementCA.pem /opt/ManagementCA.pem
RUN chmod 777 /opt/ManagementCA.pem

ADD run.sh /opt/
RUN chmod +x /opt/run.sh

CMD ["/opt/run.sh"]
