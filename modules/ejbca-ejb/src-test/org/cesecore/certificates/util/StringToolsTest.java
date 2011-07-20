/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests the StringTools class .
 * 
 * Based on EJBCA version: StringToolsTest.java 11089 2011-01-07 11:41:50Z anatom
 * 
 * @version $Id$
 */
public class StringToolsTest {
    private static Logger log = Logger.getLogger(StringToolsTest.class);

    /**
     * tests stripping whitespace
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void test01StripWhitespace() throws Exception {
        log.trace(">test01StripWhitespace()");
        String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
        assertEquals("foobarquux", StringTools.stripWhitespace(test));
        log.trace(">test01StripWhitespace()");
    }

    @Test
    public void test02IpStringToOctets() throws Exception {
        log.trace(">test02IpStringToOctets()");
        String ip = "23.34.45.167";
        byte[] octs = StringTools.ipStringToOctets(ip);
        for (int i = 0; i < octs.length; i++) {
            log.debug("octs[" + i + "]=" + (int) octs[i]);
        }
        log.trace(">test02IpStringToOctets()");
    }

    @Test
    public void test03Strip() throws Exception {
        log.trace(">test03Strip()");
        String strip1 = "foo$bar:far%";
        String stripped = StringTools.strip(strip1);
        assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly!", stripped, "foo/bar:far/");
        log.trace("<test03Strip()");
    }

    @Test
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
        assertEquals("String not stripped correctly! " + stripped, "CN=foo+CN=bar, O=Acme\\, Inc", stripped);

        log.trace("<test04Strip()");
    }

    @Test
    public void testBase64() throws Exception {
        String s1 = "C=SE, O=abc, CN=def";
        String b1 = StringTools.putBase64String(s1);
        String s2 = StringTools.getBase64String(b1);
        assertEquals(s2, s1);

        s1 = "C=SE, O=���, CN=���";
        b1 = StringTools.putBase64String(s1);
        s2 = StringTools.getBase64String(b1);
        assertEquals(s2, s1);
    }

    @Test
    public void testObfuscate() throws Exception {
        String obf = StringTools.obfuscate("foo123");
        String deobf = StringTools.deobfuscate(obf);
        assertEquals("foo123", deobf);
    }

    @Test
    public void testPbe() throws Exception {
        CryptoProviderTools.installBCProvider();
        String enc = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
        String dec = StringTools.pbeDecryptStringWithSha256Aes192(enc);
        assertEquals("foo123", dec);
    }

    @Test
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

    @Test
    public void testIpStringToOctets() throws Exception {
        String ipv4 = "192.168.4.45";
        byte[] ipv4oct = StringTools.ipStringToOctets(ipv4);
        assertNotNull(ipv4oct);
        assertEquals(4, ipv4oct.length);
        String ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        byte[] ipv6oct = StringTools.ipStringToOctets(ipv6);
        assertNotNull(ipv6oct);
        assertEquals(16, ipv6oct.length);
        String invalid = "foo";
        byte[] oct = StringTools.ipStringToOctets(invalid);
        assertNotNull(oct);
        assertEquals(0, oct.length);
        String invalidipv4 = "192.177.333.22";
        oct = StringTools.ipStringToOctets(invalidipv4);
        assertNotNull(oct);
        assertEquals(0, oct.length);
        String invalidipv6 = "2001:0db8:85a3:0000:0000:8a2e:11111:7334";
        oct = StringTools.ipStringToOctets(invalidipv6);
        assertNotNull(oct);
        assertEquals(0, oct.length);
    }

    @Test
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

    @Test
    public void testParseCertData() {
    	String certdata = "0000AAAA : DN : \"CN=foo,O=foo,C=SE\" : SubjectDN : \"CN=foo2,C=SE\"";
    	String res[] = StringTools.parseCertData(certdata);
    	assertNotNull(res);
    	assertEquals("Failed to find the administrator certificate serialnumber", res[0],"0000AAAA");
    	assertEquals("Failed to find the administrator certificate issuerDN", res[1], "CN=foo,O=foo,C=SE");
    	
    	certdata = "0000AAAA,CN=foo,O=foo,C=SE";
    	res = StringTools.parseCertData(certdata);
    	assertNotNull(res);
    	assertEquals("Failed to find the client certificate serialnumber", res[0], "0000AAAA");
    	assertEquals("Failed to find the client certificate issuerDN", res[1], "CN=foo,O=foo,C=SE");
    	
    	certdata = "0000AAAA, CN=foo,O=foo,C=SE";
    	res = StringTools.parseCertData(certdata);
    	assertNotNull(res);
    	assertEquals("Failed to find the client certificate serialnumber", res[0], "0000AAAA");
    	assertEquals("Failed to find the client certificate issuerDN", res[1], "CN=foo,O=foo,C=SE");
    }

	@Test
	public void testSplitURIs() throws Exception {
		assertEquals(Arrays.asList("aa;a", "bb;;;b", "cc"), StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc\""));
		assertEquals(Arrays.asList("aa", "bb;;;b", "cc"), StringTools.splitURIs("aa;\"bb;;;b\";\"cc\""));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;cc;"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa   ;  bb;cc  "));	// Extra white-spaces
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("  aa;bb ;cc;  "));	// Extra white-spaces
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs("aa;bb;;;;cc;"));
		assertEquals(Arrays.asList("aa", "bb", "cc"), StringTools.splitURIs(";;;;;aa;bb;;;;cc;"));
		assertEquals(Arrays.asList("aa", "b", "c", "d", "e"), StringTools.splitURIs(";;\"aa\";;;b;c;;;;d;\"e\";;;"));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("http://example.com"));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com\""));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com\";"));
		assertEquals(Collections.EMPTY_LIST, StringTools.splitURIs(""));
		assertEquals(Arrays.asList("http://example.com"), StringTools.splitURIs("\"http://example.com")); 	// No ending quote
		assertEquals(Arrays.asList("aa;a", "bb;;;b", "cc"), StringTools.splitURIs("\"aa;a\";\"bb;;;b\";\"cc")); 	// No ending quote
	}

}
