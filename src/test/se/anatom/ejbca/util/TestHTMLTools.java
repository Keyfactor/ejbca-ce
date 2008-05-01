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

package se.anatom.ejbca.util;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.ejbca.util.HTMLTools;
import org.ejbca.util.StringTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id$
 */
public class TestHTMLTools extends TestCase {
    private static Logger log = Logger.getLogger(TestHTMLTools.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestHTMLTools(String name) {
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

    public void test01JavascriptEscape() throws Exception {
        String test = "l'AC si vous l'avez";
        assertEquals("l\\'AC si vous l\\'avez", HTMLTools.javascriptEscape(test));
    }
}
