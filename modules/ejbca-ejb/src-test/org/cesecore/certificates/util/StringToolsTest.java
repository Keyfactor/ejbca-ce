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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.junit.Test;

/**
 * Tests the StringTools class .
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

    final static String FORBIDDEN_CHARS_KEY = "forbidden.characters";
    private static void forbiddenTest( final String forbidden, final String input, final String output ) {
        ConfigurationHolder.instance().setProperty(FORBIDDEN_CHARS_KEY, forbidden);
        final String stripped = StringTools.strip(input);
        if ( input.equals(output) ) {
            assertFalse("The string do NOT have chars that should be stripped!", StringTools.hasStripChars(input));
        } else {
            assertTrue("The string DO have chars that should be stripped!", StringTools.hasStripChars(input));
        }
        assertEquals("String not stripped correctly!", output, stripped);
    }
    @Test
    public void test05Strip() throws Exception {
        log.trace(">test05Strip()");
        final Object originalValue = ConfigurationHolder.instance().getProperty(FORBIDDEN_CHARS_KEY);
        try {
            final String input =  "|\n|\r|;|foo bar|!|\u0000|`|?|$|~|\\<|\\>|\\\"|\\\\";
            final String defaultOutput = "|/|/|/|foo bar|/|/|/|/|/|/|\\<|\\>|\\\"|\\\\";
            forbiddenTest(null, input, defaultOutput);
            forbiddenTest("\n\r;!\u0000%`?$~", input, defaultOutput);
            forbiddenTest("", input, input);
            forbiddenTest("ABCDEF", input, input);
            forbiddenTest("rab| oof<>\"\\", input, "/\n/\r/;/////////!/\u0000/`/?/$/~////////");
            forbiddenTest("\"", input, "|\n|\r|;|foo bar|!|\u0000|`|?|$|~|\\<|\\>|/|\\\\");
            forbiddenTest("f", input, "|\n|\r|;|/oo bar|!|\u0000|`|?|$|~|\\<|\\>|\\\"|\\\\");
        } finally {
            ConfigurationHolder.instance().setProperty(FORBIDDEN_CHARS_KEY, originalValue);
        }
        log.trace("<test05Strip()");
    }

    @Test
    public void testBase64() throws Exception {
        String s1 = "C=SE, O=abc, CN=def";
        String b1 = StringTools.putBase64String(s1);
        String s2 = StringTools.getBase64String(b1);
        assertEquals(s2, s1);

        s1 = "C=SE, O=åäö, CN=ÅÖ";
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
        assertTrue(ret);

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
    	
        certdata = "0000AAAA, CN=foo,SN=123456,O=foo,C=SE";
        res = StringTools.parseCertData(certdata);
        assertNotNull(res);
        assertEquals("Failed to find the client certificate serialnumber", res[0], "0000AAAA");
        assertEquals("Failed to find the client certificate issuerDN", "CN=foo,SN=123456,O=foo,C=SE", res[1]);

        certdata = "0000AAAA, E=ca.intern@primek-y.se,CN=foo,SN=123456,O=foo,C=SE";
        res = StringTools.parseCertData(certdata);
        assertNotNull(res);
        assertEquals("Failed to find the client certificate serialnumber", res[0], "0000AAAA");
        assertEquals("Failed to find the client certificate issuerDN", "E=ca.intern@primek-y.se,CN=foo,SN=123456,O=foo,C=SE", res[1]);
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

	@Test
	public void testB64() {
		assertNull(StringTools.getBase64String(null));
		assertEquals("", StringTools.getBase64String(""));
		assertEquals("B64:", StringTools.getBase64String("B64:"));
		assertEquals("b64:", StringTools.getBase64String("b64:"));
		assertEquals("test", StringTools.getBase64String(StringTools.putBase64String("test")));
		assertEquals("test~!\"#%&/()", StringTools.putBase64String("test~!\"#%&/()", true));
		assertEquals("test~!\"#%&/()", StringTools.getBase64String(StringTools.putBase64String("test~!\"#%&/()", true)));
		assertEquals("test~!\"#%&/()", StringTools.getBase64String(StringTools.putBase64String("test~!\"#%&/()", false)));
		assertEquals("B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("åäöüè"));
		assertEquals("B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("åäöüè", true));
		assertEquals("åäöüè", StringTools.getBase64String(StringTools.putBase64String("åäöüè", true)));
        assertEquals("åäöüè", StringTools.getBase64String(StringTools.putBase64String("åäöüè", false)));
		// Check against unicodes as well, just to be sure encodiings are not messed up by eclipse of anything else
        assertEquals("B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("\u00E5\u00E4\u00F6\u00FC\u00E8"));
        assertEquals("B64:w6XDpMO2w7zDqA==", StringTools.putBase64String("\u00E5\u00E4\u00F6\u00FC\u00E8", true));
        assertEquals("\u00E5\u00E4\u00F6\u00FC\u00E8", StringTools.getBase64String(StringTools.putBase64String("åäöüè", true)));
		assertEquals("\u00E5\u00E4\u00F6\u00FC\u00E8", StringTools.getBase64String(StringTools.putBase64String("åäöüè", false)));
	}
	
	@Test
	public void testStripXss() {
		final String str = "foo<tag>tag</tag>!";
		String ret = StringTools.strip(str);
		assertEquals("<> should not have been stripped, but ! should have: ", "foo<tag>tag</tag>/", ret);
		ret = StringTools.stripUsername(str);
		assertEquals("<> should have been stripped and so should !", "foo/tag/tag//tag//", ret);
	}

    @Test
    public void testCleanXForwardedFor() {
        assertEquals("192.0.2.43, 2001:db8:cafe::17", StringTools.getCleanXForwardedFor("192.0.2.43, 2001:db8:cafe::17"));
        assertEquals("192.0.2.43", StringTools.getCleanXForwardedFor("192.0.2.43"));
        assertEquals("2001:db8:cafe::17", StringTools.getCleanXForwardedFor("2001:db8:cafe::17"));
        assertEquals("192.0.2.43, 2001:db8:cafe::17", StringTools.getCleanXForwardedFor(" 192.0.2.43, 2001:db8:cafe::17 "));
        assertEquals("192.0.2.43, 2001:db8:cafe::17", StringTools.getCleanXForwardedFor("192.0.2.43, 2001:DB8:CAFE::17"));
        assertEquals(null, StringTools.getCleanXForwardedFor(null));
        assertEquals("??c?????a?e????a?e???????????????", StringTools.getCleanXForwardedFor("<script>alert(\"alert!\");</stript>"));
    }
    
    @Test
    public void testPasswordEncryptionAndObfuscation() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {
        String obf = StringTools.obfuscate("foo123");
        String deobf = StringTools.deobfuscate(obf);
        assertEquals("Encrypted/decrypted password does not match", "foo123", deobf);

        String pbe = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
        String pwd = StringTools.pbeDecryptStringWithSha256Aes192(pbe);
        assertEquals("Encrypted/decrypted password does not match", "foo123", pwd);
    }
}
