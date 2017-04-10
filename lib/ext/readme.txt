
These are jars used for external activities, not needed for running EJBCA.

External dependencies used just for building (java classes):
servlet-2.3.jar
mailapi.jar (javaMail v1.5.5)

User to build docs (license apache):
jdom-b9.jar (I think)
velocity-dep-1.4.jar

Used to run regular JUnit tests (license CPL):
junit-4.11.jar

Dependencies required to run some ExternalRA Tests
geronimo-osgi-locator-1.1.jar (Apache 2.0)
slf4j-api-1.7.22.jar (Apache/MIT/BSD/CDDL)

Only used to get rid of warnings when running some CLIs 
(EJB CLI and Statedump), on versions of JBoss/WildFly that uses SLF4j.
slf4j-log4j12-1.7.22,jar (Apache/MIT/BSD/CDDL)
