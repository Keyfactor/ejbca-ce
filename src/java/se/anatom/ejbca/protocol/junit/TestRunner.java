package se.anatom.ejbca.protocol.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import junit.framework.*;


/**
 * Main test class
 *
 * @version $Id: TestRunner.java,v 1.3 2002/10/24 20:02:53 herrvendil Exp $
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
        junit.textui.TestRunner.run(suite(args));
    }

    private void cleanUp() {
        log.debug(">cleanUp()");
        log.debug("<cleanUp()");
    }

    /**
     * Sets up test suite
     *
     * @return none
     */
    public static Test suite(String[] args) {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        if ((args.length > 0) && args[0].equals("web")) {
            // Webtests using httpuint to send stuff to ejbca@localhost
            suite.addTest(ProtocolHttpTest.suite());
        } else {
            suite.addTest(new TestSuite(TestMessages.class));
        }

        log.debug("<suite()");

        return suite;
    }
}
