package se.anatom.ejbca.webdist.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import junit.framework.*;


/**
 * Main test class
 *
 * @version $Id: TestRunner.java,v 1.1 2003-12-05 14:21:59 anatom Exp $
 */
public class TestRunner extends Object {
    private static Logger log = Logger.getLogger(TestRunner.class);

    /**
     * Main
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
     * @return cmd line args
     */
    public static Test suite() {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest(new TestSuite(WebdistHttpTest.class));

        log.debug("<suite()");

        return suite;
    }
}
