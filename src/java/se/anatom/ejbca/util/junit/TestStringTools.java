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
 
package se.anatom.ejbca.util.junit;

import org.apache.log4j.Logger;

import junit.framework.*;

import se.anatom.ejbca.util.StringTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestStringTools.java,v 1.4 2004-04-16 07:38:59 anatom Exp $
 */
public class TestStringTools extends TestCase {
    private static Logger log = Logger.getLogger(TestStringTools.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestStringTools(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
        log.debug(">tearDown()");
        log.debug("<tearDown()");
    }

    /**
     * tests stipping whitespace
     *
     * @throws Exception error
     */
    public void test01StripWhitespace() throws Exception {
        log.debug(">test01StripWhitespace()");

        String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
        assertEquals("foobarquux", StringTools.stripWhitespace(test));
        log.debug(">test01StripWhitespace()");
    }
}
