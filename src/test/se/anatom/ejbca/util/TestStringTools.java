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

package se.anatom.ejbca.util;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestStringTools.java,v 1.9 2006-08-02 11:23:21 anatom Exp $
 */
public class TestStringTools extends TestCase {
    private static Logger log = Logger.getLogger(TestStringTools.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestStringTools(String name) {
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
     * tests stipping whitespace
     *
     * @throws Exception error
     */
    public void test01StripWhitespace() throws Exception {
        log.debug(">test01StripWhitespace()");
        String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
        assertEquals("foobarquux", StringTools.stripWhitespace(test));
        log.debug(">test01StripWhitespace()");
    }

    public void test02IpStringToOctets() throws Exception {
        log.debug(">test02IpStringToOctets()");
        String ip = "23.34.45.167";
        byte[] octs = StringTools.ipStringToOctets(ip);
        for (int i=0;i<octs.length;i++) {
            log.debug("octs["+i+"]="+(int)octs[i]);
        }
        log.debug(">test02IpStringToOctets()");
    }
    public void test03Strip() throws Exception {
    	log.debug(">test03Strip()");
    	String strip1 = "foo$bar:far%";
    	String stripped = StringTools.strip(strip1);
    	assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
    	assertEquals("String not stripped correctly!", stripped, "foo/bar:far/");
		log.debug("<test03Strip()");
    }
    public void test04Strip() throws Exception {
        log.debug(">test04Strip()");
        String strip1 = "CN=foo, O=Acme\\, Inc, OU=;\\/<>bar";
        String stripped = StringTools.strip(strip1);
        assertTrue("String has chars that should be stripped!", StringTools.hasSqlStripChars(strip1));
        assertEquals("String not stripped correctly!", stripped, "CN=foo, O=Acme\\, Inc, OU=/////bar");
        log.debug("<test04Strip()");
    }
    public void testBase64() throws Exception {
        String s1 = "C=SE, O=abc, CN=def";
        String b1 = StringTools.putBase64String(s1);
        String s2 = StringTools.getBase64String(b1);
        assertEquals(s2,s1);

        s1 = "C=SE, O=ÅÄÖ, CN=åäö";
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
        CertTools.installBCProvider();
        String enc = StringTools.pbeEncryptStringWithSha256Aes192("foo123");
        String dec = StringTools.pbeDecryptStringWithSha256Aes192(enc);
        assertEquals("foo123", dec);
    }
}
