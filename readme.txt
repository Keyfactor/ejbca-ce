
EJBCA
-----
The goal with EJBCA is to create a fully functional CA built in Java. EJBCA builds on the J2EE platform to 
create a robust, high performance, transactional, platform independent, flexible, modular and component based 
CA to be used either standalone or integrated into any J2EE application.

FEATURES
--------

Build on EJB 1.1 specification.

Flexible, component based architecture.
Multiple levels of CAs.
Standalone or integrated in any J2EE application.
Individual enrollment or batch production.
Enrollment through browsers and/or other applications through open APIs and tools.
Follows X509 and PKIX (RFC2459) standards where applicable.
Configurable certificate contents.
Revocation of certificates and CRL creation using scheduled jobs.
URL-based CRLDistribution Points according to (RFC2459).

SECURITY
--------

Security is discussed below in the chapter about configuration and in 'security.txt'. 
Please take a minute to thorougly consider the security implications and make sure you know what you are doing when you are setting up a CA.

DEPENDENCIES
------------
EJBCA uses the OpenSource JCE crypto provider from Bouncycastle (www.bouncycastle.org).
EJBCA is developed on the OpenSource J2EE application server JBoss (www.jboss.org).

PLATFORMS
---------
EJBCA is completely written in Java and sould as such run on any platoform where a J2EE server runs.
Development and testing is performed On Linux and Windows2000 platforms.

BUILD
-----

Needed to build and run are:
JDK (1.3.1_x)
JBOSS 2.4.x (with Tomcat) (www.jboss.org)
Ant 1.4 to build (http://jakarta.apache.org/ant/)

Simply unpack the archive in a directory and run "ant" to build everything.

Copy the Boucycastle JCE provider lib/bcprov.jar to the directory jboss/lib/ext in, it will be added to JBoss's classpath 
automatically when JBoss is started.

Set the environment variable JBOSS_HOME to the directory where JBoss's root is (/jboss). This is done so the deploy script will know where files are to be copied, they are copied to the $JBOSS_HOME/deploy directory.

CONFIGURE
---------

Now when everything is installed, there are a few things to configure before starting JBOSS and running everything.
Most important, to run the CA a keystore must be in the directory designated by the item 'keyStore' in src/ca/META-INF/ejb-jar.xml (default /tmp/server.p12). A test keyStore is provided in 'src/ca/keystore/server.p12'.

For the impatient:
1. Copy 'src/ca/keyStore/server.p12' to /tmp.
2. Start JBoss, jars and wars should be deployed.
3. Run the tests with 'runtest.sh/bat'.

Setting up your own CA:

The CA uses a keystore, which is configured at deployment by editing 'src/ca/META-INF/ejb-jar.xml'. Of special interest is the 'keyStore' entry, which points to the keystore holding the CAs private key and certificate chain.
There are several ways to generate a keystore depending on if the CA is a root CA or subordinate to another CA.

Root CA:
run 'ca.sh/bat makeroot' and enter all required parameters.
Ex: 'ca.sh makeroot C=SE,O=AnaTom,CN=EJBCA 1024 365 /tmp/server.p12 foo123
will create a root CA with the DN 'C=SE,O=AnaTom,CN=EJBCA'. The keylength is 1024 bit (RSA) and the validity of the root certificate is 365 days. The CAs keystore will be stored in 'tmp/server.p12' and be protected by the password 'foo123'.
Now edit 'src/ca/META-INF/ejb-jar.xml' to reflect the values you entered for 'keyStore' and 'keyStorePass'.

Subordinate CA:
run 'ca.sh/bat makereq' and enter all required parameters.
The result will be a PKCS10 certificate request which must be processed by the CA that will certify this subordinate CA.
//TODO: more description and examples.
run 'ca.sh/bat recrep' and enter all required parameters to receive the certificate reply sent by the CA certifying this subordinate CA. The certificate reply is simply a DER-encoded certificate.
Now edit 'src/ca/META-INF/ejb-jar.xml' to reflect the values you entered for 'keyStore' and 'keyStorePass'.

OBS! Don't forget to configure JBoss for security! See 'security.txt'.
Security is CRITICAL for a CA.

DEPLOY
------
After configuration, if you have edited the xml-files manually, please run "ant" to rebuild jars and wars. If youe are using a deployment tool, this may not be needed, consult your documentation for the tool.

Run deploy.sh/bat to install the EJBs and WARs (they are copied to the $JBOSS_HOME/deploy directory).

RUN
---

Start JBoss with 'run_whith_tomcat.sh/bat'. JBOSS shoudl start up and deploy our beans and servlets without error messages.

Run the testprograms with 'runtests.sh/bat' and watch the lovely debug output and logs in JBoss.

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

Note on Mozilla certs:
For Netscape/Mozilla to be able to verify client certificates the CA-certificates must have the extensions BasicConstraints and AuthorityKeyIdentifier.
Client certificates also need AuthorityKeyIdentifier

Not on IE certs:
For IE to verify client certs, the ordering in the DN must be strictly the same in both client and CA certs. Possibly that it must also be in a specific order.
