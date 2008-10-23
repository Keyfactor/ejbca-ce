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

import org.ejbca.util.CertTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id$
 */
public class TestDnComponents extends TestCase {

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestDnComponents(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects();
        assertEquals(25, s.length);
        assertEquals("telephonenumber",s[0]);
        assertEquals("businesscategory",s[2]);
        assertEquals("postalcode",s[3]);
        assertEquals("unstructuredaddress",s[4]);
        assertEquals("unstructuredname",s[5]);
        assertEquals("dn",s[9]);
        assertEquals("uid",s[10]);
        assertEquals("cn",s[11]);
        assertEquals("t",s[18]);
        assertEquals("c",s[24]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(25, s1.length);
        assertEquals("telephonenumber",s1[24]);
        assertEquals("businesscategory",s1[22]);
        assertEquals("postalcode",s1[21]);
        assertEquals("unstructuredaddress",s1[20]);
        assertEquals("unstructuredname",s1[19]);
        assertEquals("uid",s1[14]);
        assertEquals("cn",s1[13]);
        assertEquals("t",s1[6]);
        assertEquals("c",s1[0]);

        String[] s2 = DnComponents.getDnObjects();
        assertEquals(25, s2.length);
        assertEquals("businesscategory",s2[2]);
        assertEquals("postalcode",s2[3]);
        assertEquals("unstructuredaddress",s2[4]);
        assertEquals("unstructuredname",s2[5]);
        assertEquals("uid",s2[10]);
        assertEquals("cn",s2[11]);
        assertEquals("t",s2[18]);
        assertEquals("c",s2[24]);

    }
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,C=se");
        assertEquals("CN=oid,C=se", dn);
    }

}
