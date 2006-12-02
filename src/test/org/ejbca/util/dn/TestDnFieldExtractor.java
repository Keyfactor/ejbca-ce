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


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestDnFieldExtractor.java,v 1.1 2006-12-02 11:18:31 anatom Exp $
 */
public class TestDnFieldExtractor extends TestCase {
    private static Logger log = Logger.getLogger(TestDnFieldExtractor.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestDnFieldExtractor(String name) {
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

    /**
     * @throws Exception error
     */
    public void test01CheckDnFields() throws Exception {
    	String dn = "cn=Tomas Gustavsson,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	int[] i = extractor.getNumberOfFields();
    	assertEquals(16,i.length);
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
    	
    	dn = "cn=Tomas Gustavsson,1.1.1.1=Foo,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
    	illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	other = extractor.existsOther();
    	assertTrue(other);
    	dn = "qqq,cn=Tomas Gustavsson,1.1.1.1=Foo,o=PrimeKey,L=Stockholm,dc=PrimeKey,DC=com";
    	extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);
     	illegal = extractor.isIllegal();
    	assertTrue(illegal);
    }

    /**
     * @throws Exception error
     */
    public void test01CheckAltNameFields() throws Exception {
    	String dn = "DnsName=foo.bar.se,rfc822Name=foo@bar.se";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    	int[] i = extractor.getNumberOfFields();
    	assertEquals(11,i.length);
    	String dns = extractor.getField(DNFieldExtractor.DNSNAME, 0);
    	assertEquals("foo.bar.se", dns);
    	boolean illegal = extractor.isIllegal();
    	assertFalse(illegal);
    	boolean other = extractor.existsOther();
    	assertFalse(other);
    	String email= extractor.getField(DNFieldExtractor.RFC822NAME, 0);
    	assertEquals("foo@bar.se", email);
    	
    }
}

