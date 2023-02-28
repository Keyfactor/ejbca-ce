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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Tests the DnComponents class.
 */
public class DnComponentsTest {

    @Test
    public void test01CheckObjects() throws Exception {
        String[] s = DnComponents.getDnObjects(true);
        assertEquals(36, s.length);
        int i = 0;
        assertEquals("description", s[i++]);
        assertEquals("jurisdictioncountry", s[i++]);
        assertEquals("jurisdictionstate", s[i++]);
        assertEquals("jurisdictionlocality", s[i++]);
        assertEquals("role", s[i++]);
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
        assertEquals("pid", s[i++]);
        assertEquals("vid", s[i++]);
        assertEquals("cn", s[i++]);
        assertEquals("name", s[i++]);
        i += 6;
        assertEquals("t", s[i]);
        i += 2;
        assertEquals("organizationidentifier", s[i]);
        i += 5;
        assertEquals("c", s[i]);

        String[] s1 = DnComponents.getDnObjectsReverse();
        assertEquals(36, s1.length);
        assertEquals("description", s1[35]);
        assertEquals("jurisdictioncountry", s1[34]);
        assertEquals("jurisdictionstate", s1[33]);
        assertEquals("jurisdictionlocality", s1[32]);
        assertEquals("role", s1[31]);
        assertEquals("street", s1[30]);
        assertEquals("telephonenumber", s1[28]);
        assertEquals("businesscategory", s1[26]);
        assertEquals("postalcode", s1[25]);
        assertEquals("unstructuredaddress", s1[24]);
        assertEquals("unstructuredname", s1[23]);
        assertEquals("uid", s1[18]);
        assertEquals("pid", s1[17]);
        assertEquals("vid", s1[16]);
        assertEquals("cn", s1[15]);
        assertEquals("name", s1[14]);
        assertEquals("t", s1[7]);
        assertEquals("organizationidentifier", s1[5]);
        assertEquals("c", s1[0]);

        String[] s2 = DnComponents.getDnObjects(true);
        assertEquals(36, s2.length);
        i = 0;
        assertEquals("description", s[i++]);
        i += 7;
        assertEquals("postaladdress", s2[i++]);
        assertEquals("businesscategory", s2[i++]);
        assertEquals("postalcode", s2[i++]);
        assertEquals("unstructuredaddress", s2[i++]);
        assertEquals("unstructuredname", s2[i++]);
        i += 4;
        assertEquals("uid", s2[i++]);
        assertEquals("pid", s2[i++]);
        assertEquals("vid", s2[i++]);
        assertEquals("cn", s2[i++]);
        i += 7;
        assertEquals("t", s2[i++]);
        i += 6;
        assertEquals("c", s2[i++]);

        assertEquals("2.5.4.6", DnComponents.getOid("c").toString());
        assertEquals("2.5.4.3", DnComponents.getOid("cn").toString());
        assertEquals("2.5.4.97", DnComponents.getOid("organizationidentifier").toString());
        assertEquals("2.5.4.13", DnComponents.getOid("description").toString());
        assertEquals("2.5.4.13", DnComponents.getOid("DeScRiPtIoN").toString()); // case insensitive
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
        assertEquals("ORGANIZATIONIDENTIFIER=", DnComponents.getDnExtractorFieldFromDnId(106));
    }
    
    @Test
    public void test02() {
        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            // We used to swallow this badly formatted DN string, but doesn't do that anymore. uri=fff is not a valid DN component
            final String dn = "uri=fff,CN=oid,SN=12345,NAME=name,C=se";
            CertTools.stringToBCDNString(dn);
            fail("should fail since directory string is badly formatted 'uri, is not a valid DN component: "+dn);
        } catch (IllegalArgumentException e) {
            // NOPMD: should throw
        }
        String dn = CertTools.stringToBCDNString("CN=oid,SN=12345,NAME=name,C=se");
        final X500Name name = CertTools.stringToBcX500Name(dn);
        ASN1ObjectIdentifier[] oids = name.getAttributeTypes();
        assertEquals(BCStyle.CN, oids[0]);
        assertEquals(BCStyle.NAME, oids[1]);
        assertEquals(BCStyle.SERIALNUMBER, oids[2]);
        assertEquals(BCStyle.C, oids[3]);
        assertEquals("CN=oid,Name=name,SN=12345,C=se", dn);

        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            // We used to swallow this badly formatted DN string, but doesn't do that anymore. =fff is not a valid DN component
            final String dn1 = "SURNAME=Json,=fff,Description=test,CN=oid,SN=12345,NAME=name,C=se";
            CertTools.stringToBCDNString(dn1);
            fail("should fail since directory string is badly formatted '=fff, is not a valid DN component: "+dn1);
        } catch (StringIndexOutOfBoundsException e) {
            // NOPMD: should throw
        }
        String dn1 = CertTools.stringToBCDNString("SURNAME=Json,Description=test,CN=oid,SN=12345,NAME=name,C=se");
        final X500Name name1 = CertTools.stringToBcX500Name(dn1);
        ASN1ObjectIdentifier[] oids1 = name1.getAttributeTypes();
        assertEquals(CeSecoreNameStyle.DESCRIPTION, oids1[0]);
        assertEquals(BCStyle.CN, oids1[1]);
        assertEquals(BCStyle.NAME, oids1[2]);
        assertEquals(BCStyle.SERIALNUMBER, oids1[3]);
        assertEquals(BCStyle.SURNAME, oids1[4]);
        assertEquals(BCStyle.C, oids1[5]);
        assertEquals("description=test,CN=oid,Name=name,SN=12345,SURNAME=Json,C=se", dn1);

        try {
            // Behavior changed with introduction of multi-valued RDNs and using IETFUtils.rDNsFromString, in ECA-3934
            // We used to swallow this badly formatted DN string, but doesn't do that anymore. =fff is not a valid DN component
            final String dn2 = "jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,=fff,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se";
            CertTools.stringToBCDNString(dn2);
            fail("should fail since directory string is badly formatted '=fff, is not a valid DN component: "+dn2);
        } catch (StringIndexOutOfBoundsException e) {
            // NOPMD: should throw
        }
        String dn2 = CertTools.stringToBCDNString("jurisdictionCountry=SE,jurisdictionState=Stockholm,SURNAME=Json,CN=oid,jurisdictionLocality=Solna,SN=12345,unstructuredname=foo.bar.com,unstructuredaddress=1.2.3.4,NAME=name,C=se");
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
