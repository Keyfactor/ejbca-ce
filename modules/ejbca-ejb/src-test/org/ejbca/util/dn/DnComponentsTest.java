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
 * Tests the DnComponents class.
 *
 * @version $Id$
 */
public class DnComponentsTest extends TestCase {

    /**
     * @param name name
     */
    public DnComponentsTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects();
        assertEquals(28, s.length);
        int i = 0;
        assertEquals("street",s[i++]);
        assertEquals("pseudonym",s[i++]);
        assertEquals("telephonenumber",s[i++]);
        i++;
        assertEquals("businesscategory",s[i++]);
        assertEquals("postalcode",s[i++]);
        assertEquals("unstructuredaddress",s[i++]);
        assertEquals("unstructuredname",s[i++]);
        i+=3;
        assertEquals("dn",s[i++]);
        assertEquals("uid",s[i++]);
        assertEquals("cn",s[i++]);
        assertEquals("name",s[i++]);
        i+=6;
        assertEquals("t",s[i]);
        i+=6;
        assertEquals("c",s[i]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(28, s1.length);
        assertEquals("street",s1[27]);
        assertEquals("telephonenumber",s1[25]);
        assertEquals("businesscategory",s1[23]);
        assertEquals("postalcode",s1[22]);
        assertEquals("unstructuredaddress",s1[21]);
        assertEquals("unstructuredname",s1[20]);
        assertEquals("uid",s1[15]);
        assertEquals("cn",s1[14]);
        assertEquals("name",s1[13]);
        assertEquals("t",s1[6]);
        assertEquals("c",s1[0]);

        String[] s2 = DnComponents.getDnObjects();
        assertEquals(28, s2.length);
        assertEquals("businesscategory",s2[4]);
        assertEquals("postalcode",s2[5]);
        assertEquals("unstructuredaddress",s2[6]);
        assertEquals("unstructuredname",s2[7]);
        assertEquals("uid",s2[12]);
        assertEquals("cn",s2[13]);
        assertEquals("t",s2[21]);
        assertEquals("c",s2[27]);

    }
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,SN=12345,NAME=name,C=se");
        assertEquals("CN=oid,Name=name,SERIALNUMBER=12345,C=se", dn);
    }

}
