package se.anatom.ejbca.ca.caadmin.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import junit.framework.*;


/**
 * main test class
 *
 * @version $Id: TestRunnerStart.java,v 1.1 2004-03-14 13:49:02 herrvendil Exp $
 */
public class TestRunnerStart extends Object {
    private static Logger log = Logger.getLogger(TestRunnerStart.class);

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
		suite.addTest( new TestSuite( TestCAs.class ));
        log.debug("<suite()");

        return suite;
    }
}
