package se.anatom.ejbca.util.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import junit.framework.*;

/**
 *
 * @version $Id: TestRunner.java,v 1.4 2003-04-01 11:19:16 scop Exp $
 */
public class TestRunner extends Object {

    private static Logger log = Logger.getLogger(TestRunner.class);

    public static void main (String[] args) {
        BasicConfigurator.configure();
        junit.textui.TestRunner.run (suite());
    }

    private void cleanUp() {
        log.debug(">cleanUp()");
        log.debug("<cleanUp()");
    }

    public static Test suite ( ) {
        log.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest( new TestSuite( TestCertTools.class ));
        suite.addTest( new TestSuite( TestStringTools.class ));

        log.debug("<suite()");
        return suite;
    }
}
