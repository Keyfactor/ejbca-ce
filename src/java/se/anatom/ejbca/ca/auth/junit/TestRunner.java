package se.anatom.ejbca.ca.auth.junit;

import junit.framework.*;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;


/**
 * Main test class
 *
 * @version $Id: TestRunner.java,v 1.4 2003-06-26 11:43:22 anatom Exp $
 */
public class TestRunner extends Object {
    private static Logger log = Logger.getLogger(TestRunner.class);

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        BasicConfigurator.configure();
        junit.textui.TestRunner.run(suite());
    }

    private void cleanUp() {
        log.debug(">cleanUp()");
        log.debug("<cleanUp()");
    }

    /**
     * Sets up tests
     *
     * @return none
     */
    public static Test suite() {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest(new TestSuite(TestAuthenticationSession.class));

        log.debug("<suite()");

        return suite;
    }
}
