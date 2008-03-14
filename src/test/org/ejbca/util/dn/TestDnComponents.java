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

package org.ejbca.util.dn;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestDnComponents.java,v 1.3 2008-03-14 14:09:08 anatom Exp $
 */
public class TestDnComponents extends TestCase {
    private static Logger log = Logger.getLogger(TestDnComponents.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestDnComponents(String name) {
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

    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects();
        assertEquals(23, s.length);
        assertEquals("businesscategory",s[0]);
        assertEquals("postalcode",s[1]);
        assertEquals("unstructuredaddress",s[2]);
        assertEquals("unstructuredname",s[3]);
        assertEquals("dn",s[7]);
        assertEquals("uid",s[8]);
        assertEquals("cn",s[9]);
        assertEquals("t",s[16]);
        assertEquals("c",s[22]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(23, s1.length);
        assertEquals("businesscategory",s1[22]);
        assertEquals("postalcode",s1[21]);
        assertEquals("unstructuredaddress",s1[20]);
        assertEquals("unstructuredname",s1[19]);
        assertEquals("uid",s1[14]);
        assertEquals("cn",s1[13]);
        assertEquals("t",s1[6]);
        assertEquals("c",s1[0]);

        String[] s2 = DnComponents.getDnObjects();
        assertEquals(23, s2.length);
        assertEquals("businesscategory",s2[0]);
        assertEquals("postalcode",s2[1]);
        assertEquals("unstructuredaddress",s2[2]);
        assertEquals("unstructuredname",s2[3]);
        assertEquals("uid",s2[8]);
        assertEquals("cn",s2[9]);
        assertEquals("t",s2[16]);
        assertEquals("c",s2[22]);

    }
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,C=se");
        System.out.println(dn);
    }

}
