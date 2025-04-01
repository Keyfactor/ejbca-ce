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

import java.util.HashMap;

import com.keyfactor.util.certificate.DnComponents;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


/**
 * Tests the DNFieldExtractor class.
 */
public class DnFieldExtractorUnitTest {

    @Test
    public void test01CheckDnFields() throws Exception {
    	final String comp = DnComponents.getDnExtractorFieldFromDnId(34);
    	assertEquals("DN=", comp);
    	String dn = "name=tomas,street=a street, role=Test Role, pseudonym=pseudo,cn=Tomas Gustavsson,o=PrimeKey,organizationidentifier=12345,"
                + "L=Stockholm,dc=PrimeKey,DC=com,description=Test DN,vid=FFF1,pid=8000,uniqueIdentifier=N62892,CertificationID=BSI-K-TR-1234-2023,"
                + "legalEntityIdentifier=MCTest1,markType=Prior Use Mark,wordMark=MarkCertTest,priorUseMarkSourceURL=https://markcerts.example.com";
    	// uniqueIdentifier should be a ASN.1 BITSTRING, see X.520 6.2.7, but that is too advanced for customers so they just assume a normal UTF8String
    	// CertificationID is specified in TR03145-5, Note that the certification ID is issued by the certification authority and has the following notation:
    	// BSI-K-TR-"four digit number"-"year as four digit"
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	final HashMap<Integer, Integer> i = extractor.getNumberOfFields();
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals(54, i.size());
        } else {
            assertEquals(32, i.size());
        }
    	String cn = extractor.getField(DNFieldExtractor.CN, 0);
    	assertEquals("Tomas Gustavsson", cn);
    	cn = extractor.getField(DNFieldExtractor.CN, 1);
    	assertEquals("",cn);
    	String dc = extractor.getField(DNFieldExtractor.DC, 0);
    	assertEquals("PrimeKey", dc);
    	dc = extractor.getField(DNFieldExtractor.DC, 1);
    	assertEquals("com", dc);
    	final String l = extractor.getField(DNFieldExtractor.L, 0);
    	assertEquals("Stockholm", l);
    	final String name = extractor.getField(DNFieldExtractor.NAME, 0);
    	assertEquals("tomas", name);
    	final String street = extractor.getField(DNFieldExtractor.STREET, 0);
    	assertEquals("a street", street);
    	final String pseudo = extractor.getField(DNFieldExtractor.PSEUDONYM, 0);
    	assertEquals("pseudo", pseudo);
    	final String description = extractor.getField(DNFieldExtractor.DESCRIPTION, 0);
        assertEquals("Test DN", description);
        final String role = extractor.getField(DNFieldExtractor.ROLE, 0);
        assertEquals("Test Role", role);
    	int num = extractor.getNumberOfFields(DNFieldExtractor.DC);
    	assertEquals(2, num);
    	num = extractor.getNumberOfFields(DNFieldExtractor.O);
    	assertEquals(1, num);
        num = extractor.getNumberOfFields(DNFieldExtractor.ORGANIZATIONIDENTIFIER);
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals(1, num);
        } else {
            assertEquals(0, num);
        }
        final String oi = extractor.getField(DNFieldExtractor.ORGANIZATIONIDENTIFIER, 0);
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals("12345", oi);
        } else {
            assertEquals("", oi);
        }
    	String fieldstr = extractor.getFieldString(DNFieldExtractor.CN);
    	assertEquals("CN=Tomas Gustavsson", fieldstr);
    	fieldstr = extractor.getFieldString(DNFieldExtractor.DC);
    	assertEquals("DC=PrimeKey,DC=com", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.VID);
        assertEquals("VID=FFF1", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.PID);
        assertEquals("PID=8000", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.UNIQUEIDENTIFIER);
        assertEquals("UNIQUEIDENTIFIER=N62892", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.CERTIFICATIONID);
        assertEquals("CERTIFICATIONID=BSI-K-TR-1234-2023", fieldstr);
        final String lei = extractor.getField(DNFieldExtractor.LEGALENTITYIDENTIFIER, 0);
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals("MCTest1", lei);
        } else {
            assertEquals("", lei);
        }
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
        if (DnComponents.enterpriseMappingsExist()) {
            assertFalse(other);
        } else {
            assertTrue(other);
        }
    	dn = "dn=qualifier,cn=Tomas Gustavsson,1.1.1.1=Foo,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertTrue(other);
    	num = extractor.getNumberOfFields(34);
    	assertEquals(1, num);
    	String field = extractor.getField(34,0);
    	assertEquals("qualifier", field);
    	field = extractor.getField(DNFieldExtractor.CN,0);
    	assertEquals("Tomas Gustavsson", field);
    	// Test an illegal DN string
    	dn = "qqq,cn=Tomas Gustavsson,1.1.1.1=Foo,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
     	illegal = extractor.isIllegal();
    	assertTrue(illegal);

        // An empty subject DN string is not an illegal string, we want to handle that because
    	// certificates, CSRs etc can be without a subjectDN, usually only with an altName in that case
        extractor = new DNFieldExtractor("null", DNFieldExtractor.TYPE_SUBJECTDN);
        illegal = extractor.isIllegal();
        assertFalse(illegal);
        extractor = new DNFieldExtractor(null, DNFieldExtractor.TYPE_SUBJECTDN);
        illegal = extractor.isIllegal();
        assertFalse(illegal);
        extractor = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDN);
        illegal = extractor.isIllegal();
        assertFalse(illegal);
    }

    @Test
    public void testMatterOperationalPKIDnFields() throws Exception {
        String dn = "RCACID=CACACACA00000001,ICACID=CACACACA00000003,NODEID=DEDEDEDE00010001,FABRICID=FAB000000000001D,"
                + "NOCCAT=00AA33CC,NOCCAT=00AA33DD,FWSIGNINGID=DEDEDEDE00010003";
        DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
        HashMap<Integer, Integer> map = extractor.getNumberOfFields();
        System.out.println(map);
        String fieldstr = extractor.getFieldString(DNFieldExtractor.RCACID);
        assertEquals("RCACID=CACACACA00000001", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.ICACID);
        assertEquals("ICACID=CACACACA00000003", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.NODEID);
        assertEquals("NODEID=DEDEDEDE00010001", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.FABRICID);
        assertEquals("FABRICID=FAB000000000001D", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.NOCCAT);
        assertEquals("NOCCAT=00AA33CC,NOCCAT=00AA33DD", fieldstr);
        fieldstr = extractor.getFieldString(DNFieldExtractor.FWSIGNINGID);
        assertEquals("FWSIGNINGID=DEDEDEDE00010003", fieldstr);

    }

    /**
     * @throws Exception error
     */
    @Test
    public void test01CheckAltNameFields() throws Exception {
    	String dn = "DnsName=foo.bar.se,rfc822Name=foo@bar.se,krb5principal=foo/bar@P.COM,registeredId=1.1.1.2";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	final HashMap<Integer, Integer> i = extractor.getNumberOfFields();
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals(17,i.size());
        } else {
            assertEquals(16,i.size());
        }
    	final String dns = extractor.getField(DNFieldExtractor.DNSNAME, 0);
    	assertEquals("foo.bar.se", dns);
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
    	assertFalse(other);
    	final String email= extractor.getField(DNFieldExtractor.RFC822NAME, 0);
    	assertEquals("foo@bar.se", email);
    	int num = extractor.getNumberOfFields(DNFieldExtractor.RFC822NAME);
    	assertEquals(1, num);
    	final String krb = extractor.getField(DNFieldExtractor.KRB5PRINCIPAL, 0);
    	assertEquals("foo/bar@P.COM", krb);
    	num = extractor.getNumberOfFields(DNFieldExtractor.KRB5PRINCIPAL);
    	assertEquals(1, num);
        final String regid = extractor.getField(DNFieldExtractor.REGISTEREDID, 0);
        assertEquals("1.1.1.2", regid);
        num = extractor.getNumberOfFields(DNFieldExtractor.REGISTEREDID);
        assertEquals(1, num);

    	dn = "uniformResourceId=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1,krb5principal=foo/bar@P.COM";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertFalse(other);
    	num = extractor.getNumberOfFields(DNFieldExtractor.URI);
    	assertEquals(1, num);
    	String field = extractor.getField(DNFieldExtractor.URI, 0);
    	assertEquals("http://www.a.se/", field);
    	dn = "uniformResourceIdentifier=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertFalse(other);
    	num = extractor.getNumberOfFields(DNFieldExtractor.URI);
    	assertEquals(1, num);
    	dn = "uri=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertFalse(other);
    	num = extractor.getNumberOfFields(DNFieldExtractor.URI);
    	assertEquals(1, num);
    	field = extractor.getField(DNFieldExtractor.URI, 0);
    	assertEquals("http://www.a.se/", field);
    	dn = "uniformResourceIdentifier=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertFalse(other);
    	num = extractor.getNumberOfFields(DNFieldExtractor.URI);
    	assertEquals(1, num);
    	dn = "uniformResourceId=http://www.a.se/,upn=foo@a.se,upn=foo@b.se,rfc822name=tomas@a.se,dNSName=www.a.se,dNSName=www.b.se,iPAddress=10.1.1.1";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertFalse(other);
    	num = extractor.getNumberOfFields(DNFieldExtractor.URI);
    	assertEquals(1, num);
    	field = extractor.getField(DNFieldExtractor.URI, 0);
    	assertEquals("http://www.a.se/", field);
    }

    /**
     * @throws Exception error
     */
    @Test
    public void test01CheckDirAttrFields() throws Exception {
    	final String dn = "PlaceOfBirth=Stockholm,DateOfBirth=10660911";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	HashMap<Integer, Integer> i = extractor.getNumberOfFields();
    	assertEquals(5,i.size());
    	final String dns = extractor.getField(DNFieldExtractor.PLACEOFBIRTH, 0);
    	assertEquals("Stockholm", dns);
    	final boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	final boolean other = extractor.existsOther();
    	assertFalse(other);
    	final String email= extractor.getField(DNFieldExtractor.DATEOFBIRTH, 0);
    	assertEquals("10660911", email);
    	int num = extractor.getNumberOfFields(DNFieldExtractor.DATEOFBIRTH);
    	assertEquals(1, num);

    	extractor = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	i = extractor.getNumberOfFields();
    	assertEquals(5,i.size());
    	num = extractor.getNumberOfFields(DNFieldExtractor.DATEOFBIRTH);
    	assertEquals(0, num);

    }

    @Test
    public void test02CheckDnFieldWithCommas() throws Exception {
        String dn = "cn=Hello\\, World!,dc=example,dc=com";
        DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
        String cn = extractor.getField(DNFieldExtractor.CN, 0);
        assertEquals("Hello, World!", cn);
        String fieldstr = extractor.getFieldString(DNFieldExtractor.CN);
        assertEquals("CN=Hello\\, World!", fieldstr);
        boolean illegal = extractor.isIllegal();
        assertFalse(illegal);
        boolean other = extractor.existsOther();
        assertFalse(other);
    }

    @Test
    public void test02CheckComplexDnFieldWithCommas() throws Exception {
        // special characters like < can cause problems
        final String dn = "directoryName=serialNumber=12345678\\,description=This is a\\> test/\\,name=abc123\\,2.5.4.65=Test1234";
        DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        String value = extractor.getField(DNFieldExtractor.DIRECTORYNAME, 0);
        assertEquals("serialNumber=12345678,description=This is a> test/,name=abc123,2.5.4.65=Test1234", value);
        assertFalse(extractor.isIllegal());
        assertFalse(extractor.existsOther());
    }

}

