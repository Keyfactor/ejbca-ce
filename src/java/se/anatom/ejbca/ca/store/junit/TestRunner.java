package se.anatom.ejbca.ca.store.junit;

import junit.framework.*;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;


/**
 * main test class
 *
 * @version $Id: TestRunner.java,v 1.4 2003-06-26 11:43:23 anatom Exp $
 */
public class TestRunner extends Object {
    private static Logger log = Logger.getLogger(TestRunner.class);

    /**
     * main
     *
     * @param args cmd line args
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
     * sets up test suite
     *
     * @return none
     */
    public static Test suite() {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest(new TestSuite(TestCertificateData.class));

        //suite.addTest( new TestSuite( TestPublisher.class ));
        log.debug("<suite()");

        return suite;
    }
}
