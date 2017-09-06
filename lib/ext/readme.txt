
These are jars used for external activities, not needed for running EJBCA.

External dependencies used just for building (java classes):
mailapi.jar (javaMail v1.5.5)

Used to build html docs (license apache):
jdom-b9.jar (I think)
velocity-dep-1.4.jar

Used to run regular JUnit tests (license CPL):
junit-4.11.jar

Dependencies required to run some ExternalRA Tests
geronimo-osgi-locator-1.1.jar (Apache 2.0)
slf4j-api-1.7.25.jar (Apache/MIT/BSD/CDDL)

Only used to get rid of warnings when running some CLIs 
(EJB CLI and Statedump), on versions of JBoss/WildFly that uses SLF4j.
slf4j-log4j12-1.7.25.jar (Apache/MIT/BSD/CDDL)

httpclient (here) is only used SigningDailyRollingFileAppender and is from the Apache Http Components project, using the Apache license:
commons-httpclient-3.1.jar
