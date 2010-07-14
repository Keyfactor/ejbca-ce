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

import java.util.HashMap;

import junit.framework.TestCase;

import org.apache.log4j.Logger;


/**
 * Tests the DNFieldExtractor class.
 *
 * @version $Id$
 */
public class DnFieldExtractorTest extends TestCase {
    private static Logger log = Logger.getLogger(DnFieldExtractorTest.class);

    /**

     * @param name name
     */
    public DnFieldExtractorTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        log.trace("<tearDown()");
    }

    /**
     * @throws Exception error
     */
    public void test01CheckDnFields() throws Exception {
    	String comp = DnComponents.getDnExtractorFieldFromDnId(34);
    	assertEquals("DN=", comp);
    	String dn = "name=tomas,street=a street, pseudonym=pseudo,cn=Tomas Gustavsson,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	HashMap i = extractor.getNumberOfFields();
    	assertEquals(26,i.size());
    	String cn = extractor.getField(DNFieldExtractor.CN, 0);
    	assertEquals("Tomas Gustavsson", cn);
    	cn = extractor.getField(DNFieldExtractor.CN, 1);
    	assertEquals("",cn);
    	String dc = extractor.getField(DNFieldExtractor.DC, 0);
    	assertEquals("PrimeKey", dc);
    	dc = extractor.getField(DNFieldExtractor.DC, 1);
    	assertEquals("com", dc);
    	String l = extractor.getField(DNFieldExtractor.L, 0);
    	assertEquals("Stockholm", l);
    	String name = extractor.getField(DNFieldExtractor.NAME, 0);
    	assertEquals("tomas", name);
    	String street = extractor.getField(DNFieldExtractor.STREET, 0);
    	assertEquals("a street", street);
    	String pseudo = extractor.getField(DNFieldExtractor.PSEUDONYM, 0);
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
    	
    	dn = "qqq,cn=Tomas Gustavsson,1.1.1.1=Foo,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
     	illegal = extractor.isIllegal();
    	assertTrue(illegal);
    }

    /**
     * @throws Exception error
     */
    public void test01CheckAltNameFields() throws Exception {
    	String dn = "DnsName=foo.bar.se,rfc822Name=foo@bar.se,krb5principal=foo/bar@P.COM";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	HashMap i = extractor.getNumberOfFields();
    	assertEquals(12,i.size());
        String dns = extractor.getField(DNFieldExtractor.DNSNAME, 0);
    	assertEquals("foo.bar.se", dns);
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
    	assertFalse(other);
    	String email= extractor.getField(DNFieldExtractor.RFC822NAME, 0);
    	assertEquals("foo@bar.se", email);    	
    	int num = extractor.getNumberOfFields(DNFieldExtractor.RFC822NAME);
    	assertEquals(1, num);
    	String krb = extractor.getField(DNFieldExtractor.KRB5PRINCIPAL, 0);
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
    public void test01CheckDirAttrFields() throws Exception {
    	String dn = "PlaceOfBirth=Stockholm,DateOfBirth=10660911";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	HashMap i = extractor.getNumberOfFields();
    	assertEquals(5,i.size());
    	String dns = extractor.getField(DNFieldExtractor.PLACEOFBIRTH, 0);
    	assertEquals("Stockholm", dns);
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
    	assertFalse(other);
    	String email= extractor.getField(DNFieldExtractor.DATEOFBIRTH, 0);
    	assertEquals("10660911", email);
    	int num = extractor.getNumberOfFields(DNFieldExtractor.DATEOFBIRTH);
    	assertEquals(1, num);

    	extractor = new DNFieldExtractor("", DNFieldExtractor.TYPE_SUBJECTDIRATTR);
    	i = extractor.getNumberOfFields();
    	assertEquals(5,i.size());
    	num = extractor.getNumberOfFields(DNFieldExtractor.DATEOFBIRTH);
    	assertEquals(0, num);

    }

}

