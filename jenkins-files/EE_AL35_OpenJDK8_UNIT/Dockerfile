FROM alpine:3.5

#Create Ant Dir
RUN mkdir -p /opt/ant/

#Download Ant 1.9.8
ENV ANT_SHA1 ca31bd42c27f7e63cccb219ee59930fdc943ca82
ENV ANT_HOME /opt/ant/apache-ant-1.9.8

RUN apk --no-cache add curl 

RUN cd $HOME \
    && curl -O http://archive.apache.org/dist/ant/binaries/apache-ant-1.9.8-bin.tar.gz \
    && sha1sum apache-ant-1.9.8-bin.tar.gz | grep $ANT_SHA1 \
    && tar xf apache-ant-1.9.8-bin.tar.gz \
    && mv $HOME/apache-ant-1.9.8 $ANT_HOME \
    && rm apache-ant-1.9.8-bin.tar.gz \
    && chmod -R g+rw ${ANT_HOME}
    
#Install JDK 1.8
RUN apk --update add openjdk8

#Setting Ant Params
ENV ANT_OPTS="-Xms256M -Xmx512M"

#Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"

# copy ejbca conf to /opt in the container for runtime-usage
ADD conf /opt/conf
