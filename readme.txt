
EJBCA
-----
The goal with EJBCA is to create a fully functional CA built in Java. EJBCA builds on the J2EE platform to 
create a robust, high performance, transactional, platform independent, flexible, modular and component based 
CA to be used either standalone or integrated into any J2EE application.

FEATURES
--------

Built on the EJB 1.1 specification.

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

For the others:

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
After the request has been processed by the CA the response can be received.
run 'ca.sh/bat recrep' and enter all required parameters to receive the certificate reply sent by the CA certifying this subordinate CA. The certificate reply is simply a DER-encoded certificate.
Now edit 'src/ca/META-INF/ejb-jar.xml' to reflect the values you entered for 'keyStore' and 'keyStorePass'.
EJBCA can process certification requests as well by running 'ca.sh/bat processreq' to produce a certification response for subordinate CAs

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

To enroll for certificates using browsers, open http://127.0.0.1:8080/apply/request/index.html (assuming Tomcat listens to port 8080) and use the links for your browser.

To enroll for certificates using manual methods (for server certificates for example) open  
http://127.0.0.1:8080/apply/request/apply_man.html and fill in the form.

Use the 'ra.sh/cmd' and 'ca.sh/cmd' scripts to administer EJBCA.

Note that application for certificates only work when the status of a user is NEW (one time password thing). The status is sert to GENERATED after a certificate has been issued. To issue a new certificate, the status must be reset to new, 
which can be done through administration of the RA.

To create a crl a JobRunnerSession bean is running with JNDI name 'CreateCRLSession'. To run the session and create a CRL, 
run 'jobrunner.sh/cmd CreateCRLSession'. This job should be run with regular intervals in a production CA, therefore the 
job should be launched from CRON. There must be a 'jndi.properties' file in the classpath when 'jobrunner.sh' is run.

A new CA should always issue an (empty) CRL. This can be done by running 'ca.sh/cmd createcrl'.

MANUAL
------

Configuring CA:

Comments are provided in src/ca/META-INT/ejb-jar.xml for all options available when configuring the CA. Things that can be configured are:
The CA is modular in that all parts are different session beans which implement a specified interface. Another session bean implementing the same interface can replace any part ot the CA.
Replaceable session beans are RSASession (interface ISignSession), AuthenticationSession (interface IAuthenticationSession), CertificateStoreSession (interface ICertificateStoreSession) and CreateCRLSession (interface IJobRunnerSession).

Options in RSASession:
- Keystore for the CAs private key and certificate chain.
-Certificate lifetime and extensions. Which certificate extensions should be in issued certificates and if they should be critical or not. The default values should be good, unless CRLDistributionPoint is desired. 

Options in CreateCRLSession:
-CRL lifetime and extensions. Default values should be ok.

Options in AuthenticationSession:
-Authentication module. The CA authenticates certification requests with a specified bean defined in se.anatom.ejbca.ca.auth.IAuthenticationSession. The default authentication session authenticates towards a local databes held by the RA. 
An example is provided in sampleauth of a remoteely operated database where communication from the CA to the RA is done with a HTTP-based protocol.
The Authentication module is configured by exchanging the session bean 'AuthenticationSession'.


Configuring databases:

The session beans use direct database communication (from a connection pool) in some cases. In these cases the JNDI name if the Datasource used is always 'java:/DefaultDS'.


Batch creation of certificates:

Certificates can be created batch-wise with EJBCA. The class se.anatom.ejbca.batch.BatchMakeP12 creates PKCS12 keystores for all users designated as NEW in the local RA database.
To be able to batch generate certificates, the users must be registered with clear text passwords.
//TODO: more documentation to come here...


Administrating CA:

The CA has a command line interface ca.sh/cmd. Options are:
makeroot - creates a new Root CA keystore.
makereq - generates a certification request to create a keystore for a subordinate CA.
recrep - receives a certification reply (from another CA) for the above generated request.
processreq - processes a certification request for a subordinate CA and creates a certification reply.
createcrl - issues a CRL.
getcrl - retrieves the latest CRL.

Administrating RA:

The RA has a command line interface ra.sh/cmd. Options are:
adduser - adds a user to the database, after addition a user may apply for a certificate.
deluser - removes a user from the database, any issued certificates remain active and present in the database.
setclearpwd - set a clear text password for a user, needed to generate certificates batch-wise.
setuserstatus - sets status of a user, users can only apply for certificates when their status is NEW.
finduser - find a user in the database and lists details.
listnewusers - lists all users with status NEW.
revokeuser - revokes a user and all certificates issued to the user.

Fetching certificates and CRLs:

Certificates and CRLs can be fetched through the web-interface as defined in 'webdist/dist.html'. They can also be fetched directly from the 'CertificateStoreSession' session bean.

Other deployment scenarios:

EJBCA can be run with servlets and EJBs or only with EJBs. The servlets are only a publicly available front-end to the beans. It the CA is deployed integrated in another J2EE application, 
this front-end may not be needed.
The sampleauth servlet is only an example and should never be deployed in a real production environment.


REFERENCES
----------

http://home.netscape.com/eng/security/comm4-keygen.html

Note on Mozilla certs:
For Netscape/Mozilla to be able to verify client certificates the CA-certificates must have the extensions BasicConstraints and AuthorityKeyIdentifier.
Client certificates also need AuthorityKeyIdentifier

Note on IE certs:
For IE to verify client certs, the ordering in the DN must be strictly the same in both client and CA certs. Possibly that it must also be in a specific order.
