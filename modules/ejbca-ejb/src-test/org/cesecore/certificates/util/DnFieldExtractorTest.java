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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;

import org.junit.Test;


/**
 * Tests the DNFieldExtractor class.
 *
 * @version $Id$
 */
public class DnFieldExtractorTest {
 
    @Test
    public void test01CheckDnFields() throws Exception {
    	final String comp = DnComponents.getDnExtractorFieldFromDnId(34);
    	assertEquals("DN=", comp);
    	String dn = "name=tomas,street=a street, pseudonym=pseudo,cn=Tomas Gustavsson,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	final HashMap<Integer, Integer> i = extractor.getNumberOfFields();
        if (DnComponents.enterpriseMappingsExist()) {
            assertEquals(29, i.size());
        } else {
            assertEquals(26, i.size());
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
    	int num = extractor.getNumberOfFields(DNFieldExtractor.DC);
    	assertEquals(2, num);
    	num = extractor.getNumberOfFields(DNFieldExtractor.O);
    	assertEquals(1, num);
    	String fieldstr = extractor.getFieldString(DNFieldExtractor.CN);
    	assertEquals("CN=Tomas Gustavsson", fieldstr);
    	fieldstr = extractor.getFieldString(DNFieldExtractor.DC);
    	assertEquals("DC=PrimeKey,DC=com", fieldstr);
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
    	assertFalse(other);
    	
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
    }

    /**
     * @throws Exception error
     */
    @Test
    public void test01CheckAltNameFields() throws Exception {
    	String dn = "DnsName=foo.bar.se,rfc822Name=foo@bar.se,krb5principal=foo/bar@P.COM";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	final HashMap<Integer, Integer> i = extractor.getNumberOfFields();
    	assertEquals(13,i.size());
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

}

