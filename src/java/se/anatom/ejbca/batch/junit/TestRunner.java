
package se.anatom.ejbca.batch.junit;

import org.apache.log4j.*;
import junit.framework.*;

/**
 *
 * @version $Id: TestRunner.java,v 1.2 2002-10-24 20:01:07 herrvendil Exp $
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
        suite.addTest( new TestSuite( TestBatchMakeP12.class ));

        cat.debug("<suite()");
        return suite;
    }
}

