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

package org.ejbca.util;

import junit.framework.TestCase;

import org.apache.log4j.Logger;


/**
 * Tests the StringTools class .
 *
 * @version $Id$
 */
public class HTMLToolsTest extends TestCase {
    private static Logger log = Logger.getLogger(HTMLToolsTest.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public HTMLToolsTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.trace(">setUp()");
        log.trace("<setUp()");
    }

    protected void tearDown() throws Exception {
        log.trace(">tearDown()");
        log.trace("<tearDown()");
    }

    public void test01JavascriptEscape() throws Exception {
        String test = "l'AC si vous l'avez";
        assertEquals("l\\'AC si vous l\\'avez", HTMLTools.javascriptEscape(test));
    }
}
