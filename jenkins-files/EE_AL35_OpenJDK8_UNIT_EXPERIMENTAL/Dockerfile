FROM alpine:3.5
ARG ANT_VERSION

RUN apk --no-cache add curl

RUN bash -c "echo -e PWD is: $PWD"

RUN bash -c "echo -e ANT_VERSION is: $ANT_VERSION"

RUN bash -c 'echo -e ${ls -la}'

RUN bash -c "echo -e ANT_HOME ${ANT_HOME}"

# Install JDK 1.8
RUN apk --update add openjdk8

RUN echo ${PATH}

# Updating Path
ENV PATH="${PATH}:${ANT_HOME}/bin"

RUN echo ${PATH}

# copy ejbca conf to /opt in the container for runtime-usage
# ADD conf /opt/conf
