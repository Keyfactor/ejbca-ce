
package se.anatom.ejbca.ca.sign.junit;

import org.apache.log4j.*;
import junit.framework.*;

/**
 *
 * @version $Id: TestRunner.java,v 1.2 2002-08-20 12:17:15 anatom Exp $
 */
public class TestRunner extends Object {

    static Category cat = Category.getInstance( TestRunner.class.getName() );

    public static void main (String[] args) {
        BasicConfigurator.configure();
        junit.textui.TestRunner.run (suite());
    }

    private void cleanUp() {
        cat.debug(">cleanUp()");
        cat.debug("<cleanUp()");
    }

    public static Test suite ( ) {
        cat.debug(">suite()");

        TestSuite suite = new TestSuite();
        suite.addTest( new TestSuite( TestSignSession.class ));
        //suite.addTest( new TestSuite( TestSernoGenerator.class ));

        cat.debug("<suite()");
        return suite;
    }
}

