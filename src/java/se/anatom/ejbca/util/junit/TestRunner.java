package se.anatom.ejbca.util.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import junit.framework.*;


/**
 * Main test class
 *
 * @version $Id: TestRunner.java,v 1.7 2003-09-07 16:02:05 anatom Exp $
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
        suite.addTest(new TestSuite(TestCertTools.class));
        suite.addTest(new TestSuite(TestKeyTools.class));
        suite.addTest(new TestSuite(TestStringTools.class));

        log.debug("<suite()");

        return suite;
    }
}
