/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.anatom.ejbca.protocol;

import junit.framework.Test;
import junit.framework.TestSuite;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;


/**
 * Main test class
 *
 * @version $Id: TestRunner.java,v 1.2 2005-02-16 13:11:13 anatom Exp $
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
