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
        assertEquals(27, s.length);
        assertEquals("street",s[0]);
        assertEquals("pseudonym",s[1]);
        assertEquals("telephonenumber",s[2]);
        assertEquals("businesscategory",s[4]);
        assertEquals("postalcode",s[5]);
        assertEquals("unstructuredaddress",s[6]);
        assertEquals("unstructuredname",s[7]);
        assertEquals("dn",s[11]);
        assertEquals("uid",s[12]);
        assertEquals("cn",s[13]);
        assertEquals("t",s[20]);
        assertEquals("c",s[26]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(27, s1.length);
        assertEquals("street",s1[26]);
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
        assertEquals(27, s2.length);
        assertEquals("businesscategory",s2[4]);
        assertEquals("postalcode",s2[5]);
        assertEquals("unstructuredaddress",s2[6]);
        assertEquals("unstructuredname",s2[7]);
        assertEquals("uid",s2[12]);
        assertEquals("cn",s2[13]);
        assertEquals("t",s2[20]);
        assertEquals("c",s2[26]);

    }
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,C=se");
        assertEquals("CN=oid,C=se", dn);
    }

}
