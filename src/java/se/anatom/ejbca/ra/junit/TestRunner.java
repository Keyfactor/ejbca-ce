package se.anatom.ejbca.ra.junit;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import junit.framework.*;

/**
 *
 * @version $Id: TestRunner.java,v 1.7 2003-03-10 07:22:05 herrvendil Exp $
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
        suite.addTest( new TestSuite( TestUserData.class ));
        suite.addTest( new TestSuite( TestAddLotsofUsers.class ));

        log.debug("<suite()");
        return suite;
    }
}
