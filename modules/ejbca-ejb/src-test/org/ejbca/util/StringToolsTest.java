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

package org.ejbca.util;

import junit.framework.TestCase;

import org.apache.log4j.Logger;


/**
 * Tests the StringTools class .
 *
 * @version $Id$
 */
public class StringToolsTest extends TestCase {
    private static Logger log = Logger.getLogger(StringToolsTest.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public StringToolsTest(String name) {
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
     * tests stipping whitespace
     *
     * @throws Exception error
     */
    public void test01StripWhitespace() throws Exception {
        log.trace(">test01StripWhitespace()");
        String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
        assertEquals("foobarquux", StringTools.stripWhitespace(test));
        log.trace(">test01StripWhitespace()");
    }

    public void test02IpStringToOctets() throws Exception {
        log.trace(">test02IpStringToOctets()");
        String ip = "23.34.45.167";
        byte[] octs = StringTools.ipStringToOctets(ip);
        for (int i=0;i<octs.length;i++) {
            log.debug("octs["+i+"]="+(int)octs[i]);
        }
        log.trace(">test02IpStringToOctets()");
    }
    public void test03Strip() throws Exception {
    	log.trace(">test03Strip()");
    	String strip1 = "foo$bar:far%";
    	String stripped = StringTools.strip(strip1);
    	assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
    	assertEquals("String not stripped correctly!", stripped, "foo/bar:far/");
		log.trace("<test03Strip()");
    }
    public void test04Strip() throws Exception {
        log.trace(">test04Strip()");
        String strip1 = "CN=foo, O=Acme\\, Inc, OU=;\\/\\<\\>bar";
        String stripped = StringTools.strip(strip1);
        assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly! " + stripped, "CN=foo, O=Acme\\, Inc, OU=//\\<\\>bar", stripped);

        strip1 = "CN=foo, O=Acme\\, Inc, OU=;\\/<>\"bar";
        stripped = StringTools.strip(strip1);
        assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly! " + stripped, "CN=foo, O=Acme\\, Inc, OU=//<>\"bar", stripped);

        strip1 = "CN=foo\\+bar, O=Acme\\, Inc";
        stripped = StringTools.strip(strip1);
        assertFalse("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly! " + stripped, "CN=foo\\+bar, O=Acme\\, Inc", stripped);

        // Multi-valued.. not supported by EJBCA yet.. let it through for backwards compatibility.
        strip1 = "CN=foo+CN=bar, O=Acme\\, Inc";
        stripped = StringTools.strip(strip1);
        assertFalse("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly! "+stripped, "CN=foo+CN=bar, O=Acme\\, Inc", stripped);

        log.trace("<test04Strip()");
    }
    public void testBase64() throws Exception {
        String s1 = "C=SE, O=abc, CN=def";
        String b1 = StringTools.putBase64String(s1);
        String s2 = StringTools.getBase64String(b1);
        assertEquals(s2,s1);

        s1 = "C=SE, O=���, CN=���";
        b1 = StringTools.putBase64String(s1);
        s2 = StringTools.getBase64String(b1);
        assertEquals(s2,s1);
    }
    public void testObfuscate() throws Exception {
        String obf = StringTools.obfuscate("foo123");
        String deobf = StringTools.deobfuscate(obf);
        assertEquals("foo123", deobf);
    }
    public void testPbe() throws Exception {
        CryptoProviderTools.installBCProvider();
        String enc = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
        String dec = StringTools.pbeDecryptStringWithSha256Aes192(enc);
        assertEquals("foo123", dec);
    }
    public void testKeySequence() throws Exception {
    	String oldSeq = "00001";
    	assertEquals("00002", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    	oldSeq = "92002";
    	assertEquals("92003", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    	oldSeq = "SE201";
    	assertEquals("SE202", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    	oldSeq = "SEFO1";
    	assertEquals("SEFO2", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    	oldSeq = "SEBAR";
    	assertEquals("SEBAR", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, oldSeq));
    	
    	oldSeq = "AAAAA";
    	assertEquals("AAAAB", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC, oldSeq));
    	oldSeq = "SE201";
    	assertEquals("SE202", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC, oldSeq));
    	oldSeq = "SEFAA";
    	assertEquals("SEFAB", StringTools.incrementKeySequence(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC, oldSeq));
    }

    public void testIpStringToOctets() throws Exception {
    	String ipv4 = "192.168.4.45";
    	byte[] ipv4oct = StringTools.ipStringToOctets(ipv4);
    	assertNotNull(ipv4oct);
    	assertEquals(4, ipv4oct.length);
    	String ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    	byte[] ipv6oct = StringTools.ipStringToOctets(ipv6);
    	assertNotNull(ipv6oct);
    	assertEquals(16, ipv6oct.length);
    }
    
    public void testHasSqlStripChars() throws Exception {
    	String str = "select * from Table";
    	boolean ret = StringTools.hasSqlStripChars(str);
    	assertFalse(ret);

    	str = "select * from Table; delete from password";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);
    	
    	str = "select * from User where username like 'foo\\%'";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);

    	// check that we can escape commas
    	str = "foo\\,";
    	ret = StringTools.hasSqlStripChars(str);
    	assertFalse(ret);

    	str = "foo\\;";
    	ret = StringTools.hasSqlStripChars(str);
    	assertFalse(ret);

    	// Check that escaping does not work for other characters
    	str = "foo\\?";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);

    	str = "foo\\?bar";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);

    	str = "\\?bar";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);

    	// Check special case that a slash at the end also returns bad
    	str = "foo\\";
    	ret = StringTools.hasSqlStripChars(str);
    	assertTrue(ret);

    }

}
