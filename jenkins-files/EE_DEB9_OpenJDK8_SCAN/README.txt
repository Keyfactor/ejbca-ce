
WHOAMI
----
Automated Jenkins pipeline for code quality checking using different tools.

HOWTO
----
Point Jenkins pipeline to Jenkinsfile in this directory.

Whenever a change is made to the Jenkinsfile, there is a "Dry run" checkbox that can be used to ensure that the pipeline is reloaded
without executing any stage.

DEVELOP
----
You can simulate what Jenkins does for individual containers by running commands similar to:

    docker build -t pk-dev/scan-pmd ejbca_trunk/jenkins-files/EE_DEB9_OpenJDK8_SCAN/pmd/
    docker run -it --rm -u $(id -u) --memory="1536m" --memory-swap="1536m" \
        -v /home/user/workspace/ejbca_trunk:/home/jenkins/ejbca \
        -v /home/user/workspace/code-analyzer-tools_trunk:/home/jenkins/code-analyzer-tools \
        -e "JAVA_OPTS=-Xms1024m -Xmx1024m -Xss256k -XX:MetaspaceSize=64m -XX:MaxMetaspaceSize=128m" \
        pk-dev/scan-pmd

