
EJBCA
-----
The goal with EJBCA is to create a fully functional CA built in Java. EJBCA builds on the J2EE platform to 
create a robust, high performance, transactional, platform independent, flexible, modular and component based 
CA to be used either standalone or integrated into any J2EE application.

FEATURES
--------
Flexible, component based architecture.
Multiple levels of CAs.
Standalone or integrated in any J2EE application.
Individual enrollment or batch production.
Enrollment through browsers and/or other applications through open APIs and tools.
Follows X509 and PKIX (RFC2459) standards where applicable.
Configurable certificate contents.
Revocation of certificates and CRL creation using scheduled jobs.
URL-based CRLDistribution Points according to (RFC2459).

DEPENDENCIES
------------
EJBCA uses the OpenSource JCE crypto provider from Bouncycastle (www.bouncycastle.org).
EJBCA is developed on the OpenSource J2EE application server JBoss (www.jboss.org).

PLATFORMS
---------
EJBCA is completely written in Java and sould as such run on any platoform where a J2EE server runs.
Development and testing is performed On Linux and Windows2000 platforms.

INSTALL
-------

Needed to build and run are:
JDK (1.3.1_x)
JBOSS 2.4.x (with Tomcat) (www.jboss.org)
Ant 1.4 to build (http://jakarta.apache.org/ant/)

Simply unpack the archive in a directory and run "ant" to build everything.

Copy the JCE provider lib/bcprov.jar to the directory jboss/lib/ext in, it will be added to JBoss's classpath 
automatically.

Set the environment variable JBOSS_HOME to the directory where JBoss's root is (/jboss) and run 
deploy.sh/bat to install the EJBs and WARs (they are copied to the jboss/deploy directory).

Now some things are a bit rudimentary, src/ca/keystore/server.p12 must be in the directory designated by the 
item 'keyStore' in src/ca/META-INF/ejb-jar.xml (default /tmp/server.p12).

RUN
---
Run the testprograms with runtests.sh/bat and watch the lovely debug output and logs in JBoss.

To enroll for certificates using browsers, open http://127.0.0.1:8080/apply/request/index.html (assuming 
Tomcat listens to port 8080) and use the links for your browser.

To enroll for certificates using manual methods (for server certificates for example) open  
http://127.0.0.1:8080/apply/request/apply_man.html and fill in the form.

Use the 'ra.sh/cmd' and 'ca.sh/cmd' scripts to administer EJBCA.

To create a crl a JobRunnerSession bean is running with JNDI name 'CreateCRLSession'. To run the session and create a CRL, 
run 'jobrunner.sh/cmd CreateCRLSession'. This job should be run with regular intervals in a production CA, therefore the 
job should be launched from CRON. There must be a 'jndi.properties' file in the classpath when 'jobrunner.sh' is run.

MANUAL
------
More documentation to come...

-Configuring Signer
-Configuring databases
-Batch creation of certificates
-Administrating RA and CA
-Retrieving Certificates and CRLs
-Servlets and EJBs or only EJBs?

REFERENCES
----------

http://home.netscape.com/eng/security/comm4-keygen.html
