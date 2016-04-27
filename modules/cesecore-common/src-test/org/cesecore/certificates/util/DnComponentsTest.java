/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 * Tests the DnComponents class.
 * 
 * @version $Id$
 */
public class DnComponentsTest {

    @Test
    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects(true);
        assertEquals(32, s.length);
        int i = 0;
        assertEquals("jurisdictioncountry", s[i++]);
        assertEquals("jurisdictionstate", s[i++]);
        assertEquals("jurisdictionlocality", s[i++]);
        assertEquals("street", s[i++]);
        assertEquals("pseudonym", s[i++]);
        assertEquals("telephonenumber", s[i++]);
        i++;
        assertEquals("businesscategory", s[i++]);
        assertEquals("postalcode", s[i++]);
        assertEquals("unstructuredaddress", s[i++]);
        assertEquals("unstructuredname", s[i++]);
        i += 3;
        assertEquals("dn", s[i++]);
        assertEquals("uid", s[i++]);
        assertEquals("cn", s[i++]);
        assertEquals("name", s[i++]);
        i += 6;
        assertEquals("t", s[i]);
        i += 2;
        assertEquals("organizationidentifier", s[i]);
        i += 5;
        assertEquals("c", s[i]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(32, s1.length);
        assertEquals("jurisdictioncountry", s1[31]);
        assertEquals("jurisdictionstate", s1[30]);
        assertEquals("jurisdictionlocality", s1[29]);
        assertEquals("street", s1[28]);
        assertEquals("telephonenumber", s1[26]);
        assertEquals("businesscategory", s1[24]);
        assertEquals("postalcode", s1[23]);
        assertEquals("unstructuredaddress", s1[22]);
        assertEquals("unstructuredname", s1[21]);
        assertEquals("uid", s1[16]);
        assertEquals("cn", s1[15]);
        assertEquals("name", s1[14]);
        assertEquals("t", s1[7]);
        assertEquals("organizationidentifier", s1[5]);
        assertEquals("c", s1[0]);

        String[] s2 = DnComponents.getDnObjects(true);
        assertEquals(32, s2.length);
        assertEquals("businesscategory", s2[7]);
        assertEquals("postalcode", s2[8]);
        assertEquals("unstructuredaddress", s2[9]);
        assertEquals("unstructuredname", s2[10]);
        assertEquals("uid", s2[15]);
        assertEquals("cn", s2[16]);
        assertEquals("t", s2[24]);
        assertEquals("c", s2[31]);

        assertEquals("2.5.4.6", DnComponents.getOid("c").toString());
        assertEquals("2.5.4.3", DnComponents.getOid("cn").toString());
        assertEquals("2.5.4.97", DnComponents.getOid("organizationidentifier").toString());
        assertEquals("1.3.6.1.4.1.311.60.2.1.3", DnComponents.getOid("jurisdictioncountry").toString());
        assertEquals("1.3.6.1.4.1.311.60.2.1.2", DnComponents.getOid("jurisdictionstate").toString());
        assertEquals("1.3.6.1.4.1.311.60.2.1.1", DnComponents.getOid("jurisdictionlocality").toString());
        
        assertEquals("CN=",DnComponents.getDnExtractorFieldFromDnId(2));
        assertEquals("C=",DnComponents.getDnExtractorFieldFromDnId(13));
        
        assertEquals(2, (int)DnComponents.getDnIdFromDnName("CN"));
        assertEquals(17, (int)DnComponents.getDnIdFromAltName("RFC822NAME"));
        assertEquals(17, (int)DnComponents.getDnIdFromAltName("rfc822name")); // should be case insensitive
        assertEquals(31, (int)DnComponents.getDnIdFromDirAttr("COUNTRYOFRESIDENCE"));
        assertEquals(null, DnComponents.getDnIdFromDirAttr("nonexistent123"));
    }

    @Test
    public void testEnterpriseProperties() {
        assumeTrue(DnComponents.enterpriseMappingsExist());
        assertEquals("JURISDICTIONLOCALITY=", DnComponents.getDnExtractorFieldFromDnId(103));
        assertEquals("JURISDICTIONSTATE=", DnComponents.getDnExtractorFieldFromDnId(104));
        assertEquals("JURISDICTIONCOUNTRY=", DnComponents.getDnExtractorFieldFromDnId(105));
    }
    
    @Test
    public void test02() {
        String dn = CertTools.stringToBCDNString("uri=fff,CN=oid,SN=12345,NAME=name,C=se");
        final X500Name name = CertTools.stringToBcX500Name(dn);
        ASN1ObjectIdentifier[] oids = name.getAttributeTypes();
        assertEquals(BCStyle.CN, oids[0]);
        assertEquals(BCStyle.NAME, oids[1]);
        assertEquals(BCStyle.SERIALNUMBER, oids[2]);
        assertEquals(BCStyle.C, oids[3]);
        assertEquals("CN=oid,Name=name,SN=12345,C=se", dn);

        String dn1 = CertTools.stringToBCDNString("SURNAME=Json,=fff,CN=oid,SN=12345,NAME=name,C=se");
        final X500Name name1 = CertTools.stringToBcX500Name(dn1);
        ASN1ObjectIdentifier[] oids1 = name1.getAttributeTypes();
        assertEquals(BCStyle.CN, oids1[0]);
        assertEquals(BCStyle.NAME, oids1[1]);
        assertEquals(BCStyle.SERIALNUMBER, oids1[2]);
        assertEquals(BCStyle.SURNAME, oids1[3]);
        assertEquals(BCStyle.C, oids1[4]);
        assertEquals("CN=oid,Name=name,SN=12345,SURNAME=Json,C=se", dn1);

        String dn2 = CertTools.stringToBCDNString("jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,=fff,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se");
        final X500Name name2 = CertTools.stringToBcX500Name(dn2);
        ASN1ObjectIdentifier[] oids2 = name2.getAttributeTypes();
        assertEquals(CeSecoreNameStyle.JURISDICTION_COUNTRY, oids2[0]);
        assertEquals(CeSecoreNameStyle.JURISDICTION_STATE, oids2[1]);
        assertEquals(CeSecoreNameStyle.JURISDICTION_LOCALITY, oids2[2]);
        assertEquals(CeSecoreNameStyle.UnstructuredAddress, oids2[3]);
        assertEquals(CeSecoreNameStyle.UnstructuredName, oids2[4]);
        assertEquals(BCStyle.CN, oids2[5]);
        assertEquals(BCStyle.NAME, oids2[6]);
        assertEquals(BCStyle.SERIALNUMBER, oids2[7]);
        assertEquals(BCStyle.SURNAME, oids2[8]);
        assertEquals(BCStyle.C, oids2[9]);
        assertEquals("JurisdictionCountry=SE,JurisdictionState=Stockholm,JurisdictionLocality=Solna,unstructuredAddress=1.2.3.4,unstructuredName=foo.bar.com,CN=oid,Name=name,SN=12345,SURNAME=Json,C=se", dn2);

    }

}
