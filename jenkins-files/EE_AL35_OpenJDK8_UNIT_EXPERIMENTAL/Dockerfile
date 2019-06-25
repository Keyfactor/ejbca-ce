FROM alpine:3.5

RUN apk --no-cache add curl

RUN echo ${ANT_HOME}

# Install JDK 1.8
RUN apk --update add openjdk8

# Updating Path
ENV PATH="${PATH}:${HOME}/bin:${ANT_HOME}/bin"

# copy ejbca conf to /opt in the container for runtime-usage
# ADD conf /opt/conf
