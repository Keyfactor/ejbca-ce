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

import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.log4j.Logger;


/**
 * Tests the CertTools class .
 *
 * @version $Id: TestCertTools.java,v 1.11 2005-11-13 18:33:44 herrvendil Exp $
 */
public class TestCertTools extends TestCase {
    private static Logger log = Logger.getLogger(TestCertTools.class);
    static byte[] testcert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky"
            + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB"
            + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ"
            + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw"
            + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj"
            + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0"
            + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4"
            + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ"
            + "QUOBOvc=").getBytes());

    static byte[] guidcert = Base64.decode(
            ("MIIC+zCCAmSgAwIBAgIIBW0F4eGmH0YwDQYJKoZIhvcNAQEFBQAwMTERMA8GA1UE"
            +"AxMIQWRtaW5DQTExDzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwHhcNMDQw"
            +"OTE2MTc1NzQ1WhcNMDYwOTE2MTgwNzQ1WjAyMRQwEgYKCZImiZPyLGQBARMEZ3Vp"
            +"ZDENMAsGA1UEAxMER3VpZDELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQAD"
            +"gY0AMIGJAoGBANdjsBcLJKUN4hzJU1p3cqaXhPgEjGul62/3xv+Gow+7oOYePcK8"
            +"bM5VO4zdQVWEhuGOZFaZ70YbXhei4F9kvqlN7xuG47g7DNZ0/fnRzvGY0BHmIR4Y"
            +"/U87oMEDa2Giy0WTjsmT14uzy4luFgqb2ZA3USGcyJ9hoT6j1WDyOxitAgMBAAGj"
            +"ggEZMIIBFTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDA7BgNVHSUENDAy"
            +"BggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUH"
            +"AwcwHQYDVR0OBBYEFJlDddj88zI7tz3SPfdig0gw5IWvMB8GA1UdIwQYMBaAFI1k"
            +"9WhE1WXpeezZx/kM0qsoZyqVMHgGA1UdEQRxMG+BDGd1aWRAZm9vLmNvbYIMZ3Vp"
            +"ZC5mb28uY29thhRodHRwOi8vZ3VpZC5mb28uY29tL4cECgwNDqAcBgorBgEEAYI3"
            +"FAIDoA4MDGd1aWRAZm9vLmNvbaAXBgkrBgEEAYI3GQGgCgQIEjRWeJCrze8wDQYJ"
            +"KoZIhvcNAQEFBQADgYEAq39n6CZJgJnW0CH+QkcuU5F4RQveNPGiJzIJxUeOQ1yQ"
            +"gSkt3hvNwG4kLBmmwe9YLdS83dgNImMWL/DgID/47aENlBNai14CvtMceokik4IN"
            +"sacc7x/Vp3xezHLuBMcf3E3VSo4FwqcUYFmu7Obke3ebmB08nC6gnQHkzjNsmQw=").getBytes());

    static byte[] altNameCert = Base64.decode(
            ("MIIDDzCCAfegAwIBAgIIPiL0klmu1uIwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE"
             +"AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw"
             +"HhcNMDUwODAyMTAxOTQ5WhcNMDcwODAyMTAyOTQ5WjAsMQwwCgYDVQQDEwNmb28x"
             +"DzANBgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UwXDANBgkqhkiG9w0BAQEFAANL"
             +"ADBIAkEAmMVWkkEMLbDNoB/NG3kJ22eC18syXqaHWRWc4DldFeCMGeLzfB2NklNv"
             +"hmr2kgIJcK+wyFpMkYm46dSMOrvovQIDAQABo4HxMIHuMAwGA1UdEwEB/wQCMAAw"
             +"DgYDVR0PAQH/BAQDAgWgMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcDAgYI"
             +"KwYBBQUHAwQGCCsGAQUFBwMFBggrBgEFBQcDBzAdBgNVHQ4EFgQUIV/Fck/+UVnw"
             +"tJigtZIF5OuuhlIwHwYDVR0jBBgwFoAUB/2KRYNOZxRDkJ5oChjNeXgwtCcwUQYD"
             +"VR0RBEowSIEKdG9tYXNAYS5zZYIId3d3LmEuc2WGEGh0dHA6Ly93d3cuYS5zZS+H"
             +"BAoBAQGgGAYKKwYBBAGCNxQCA6AKDAhmb29AYS5zZTANBgkqhkiG9w0BAQUFAAOC"
             +"AQEAfAGJM0/s+Yi1Ewmvt9Z/9w8X/T/02bF8P8MJG2H2eiIMCs/tkNhnlFGYYGhD"
             +"Km8ynveQZbdYvKFioOr/D19gMis/HNy9UDfOMrJdeGWiwxUHvKKbtcSlOPH3Hm0t"
             +"LSKomWdKfjTksfj69Tf01S0oNonprvwGxIdsa1uA9BC/MjkkPt1qEWkt/FWCfq9u"
             +"8Xyj2tZEJKjLgAW6qJ3ye81pEVKHgMmapWTQU2uI1qyEPYxoT9WkQtSObGI1wCqO"
             +"YmKglnd5BIUBPO9LOryyHlSRTID5z0UgDlrTAaNYuN8QOYF+DZEQxm4bSXTDooGX"
             +"rHjSjn/7Urb31CXWAxq0Zhk3fg==").getBytes());
    
    /**
     * Creates a new TestCertTools object.
     *
     * @param name DOCUMENT ME!
     */
    public TestCertTools(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();
        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void test01GetPartFromDN() throws Exception {
        log.debug(">test01GetPartFromDN()");

        // We try to examine the general case and som special cases, which we want to be able to handle
        String dn0 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn0, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn0, "O"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn0, "C"), "SE");
        assertEquals(CertTools.getPartFromDN(dn0, "cn"), "foo");
        assertEquals(CertTools.getPartFromDN(dn0, "o"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn0, "c"), "SE");

        String dn1 = "c=SE, o=AnaTom, cn=foo";
        assertEquals(CertTools.getPartFromDN(dn1, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn1, "O"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn1, "C"), "SE");
        assertEquals(CertTools.getPartFromDN(dn1, "cn"), "foo");
        assertEquals(CertTools.getPartFromDN(dn1, "o"), "AnaTom");
        assertEquals(CertTools.getPartFromDN(dn1, "c"), "SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(CertTools.getPartFromDN(dn2, "CN"), "cn");

        String dn3 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(CertTools.getPartFromDN(dn3, "CN"), "CN");

        String dn4 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn4, "CN"), "foo");

        String dn5 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(CertTools.getPartFromDN(dn5, "CN"), "foo");

        String dn6 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(CertTools.getPartFromDN(dn6, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn6, "O"), "PrimeKey");
        assertEquals(CertTools.getPartFromDN(dn6, "C"), "SE");

        String dn7 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(CertTools.getPartFromDN(dn7, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn7, "C"), "cn");

        String dn8 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(CertTools.getPartFromDN(dn8, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn8, "C"), "CN");

        String dn9 = "CN=foo, O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn9, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn9, "O"), "CN");

        String dn10 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn10, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn10, "O"), "CN");

        String dn11 = "CN=foo,CN=bar, O=CN, C=CN";
        assertEquals(CertTools.getPartFromDN(dn11, "CN"), "foo");
        assertEquals(CertTools.getPartFromDN(dn11, "O"), "CN");

        String dn12 = "CN=\"foo, OU=bar\", O=baz\\\\\\, quux,C=C";
        assertEquals(CertTools.getPartFromDN(dn12, "CN"), "foo, OU=bar");
        assertEquals(CertTools.getPartFromDN(dn12, "O"), "baz\\, quux");
        assertNull(CertTools.getPartFromDN(dn12, "OU"));

        String dn13 = "C=SE, O=PrimeKey, EmailAddress=foo@primekey.se";
        assertEquals(CertTools.getEmailFromDN(dn13), "foo@primekey.se");

        String dn14 = "C=SE, E=foo@primekey.se, O=PrimeKey";
        assertEquals(CertTools.getEmailFromDN(dn14), "foo@primekey.se");

        String dn15 = "C=SE, E=foo@primekey.se, O=PrimeKey, EmailAddress=bar@primekey.se";
        assertEquals(CertTools.getEmailFromDN(dn15), "bar@primekey.se");

        log.debug("<test01GetPartFromDN()");
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void test02StringToBCDNString() throws Exception {
        log.debug(">test02StringToBCDNString()");

        // We try to examine the general case and som special cases, which we want to be able to handle
        String dn1 = "C=SE, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn1), "CN=foo,O=AnaTom,C=SE");

        String dn2 = "C=SE, O=AnaTom, CN=cn";
        assertEquals(CertTools.stringToBCDNString(dn2), "CN=cn,O=AnaTom,C=SE");

        String dn3 = "CN=foo, O=PrimeKey, C=SE";
        assertEquals(CertTools.stringToBCDNString(dn3), "CN=foo,O=PrimeKey,C=SE");

        String dn4 = "cn=foo, o=PrimeKey, c=SE";
        assertEquals(CertTools.stringToBCDNString(dn4), "CN=foo,O=PrimeKey,C=SE");

        String dn5 = "cn=foo,o=PrimeKey,c=SE";
        assertEquals(CertTools.stringToBCDNString(dn5), "CN=foo,O=PrimeKey,C=SE");

        String dn6 = "C=SE, O=AnaTom, CN=CN";
        assertEquals(CertTools.stringToBCDNString(dn6), "CN=CN,O=AnaTom,C=SE");

        String dn7 = "C=CN, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn7), "CN=foo,O=AnaTom,C=CN");

        String dn8 = "C=cn, O=AnaTom, CN=foo";
        assertEquals(CertTools.stringToBCDNString(dn8), "CN=foo,O=AnaTom,C=cn");

        String dn9 = "CN=foo, O=PrimeKey, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn9), "CN=foo,O=PrimeKey,C=CN");

        String dn10 = "CN=foo, O=PrimeKey, C=cn";
        assertEquals(CertTools.stringToBCDNString(dn10), "CN=foo,O=PrimeKey,C=cn");

        String dn11 = "CN=foo, O=CN, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn11), "CN=foo,O=CN,C=CN");

        String dn12 = "O=PrimeKey,C=SE,CN=CN";
        assertEquals(CertTools.stringToBCDNString(dn12), "CN=CN,O=PrimeKey,C=SE");

        String dn13 = "O=PrimeKey,C=SE,CN=CN, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn13), "CN=CN,OU=FooOU,O=PrimeKey,C=SE");

        String dn14 = "O=PrimeKey,C=CN,CN=CN, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn14), "CN=CN,OU=FooOU,O=PrimeKey,C=CN");

        String dn15 = "O=PrimeKey,C=CN,CN=cn, OU=FooOU";
        assertEquals(CertTools.stringToBCDNString(dn15), "CN=cn,OU=FooOU,O=PrimeKey,C=CN");

        String dn16 = "CN=foo, CN=bar,O=CN, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn16), "CN=foo,CN=bar,O=CN,C=CN");

        String dn17 = "CN=foo,CN=bar, O=CN, O=C, C=CN";
        assertEquals(CertTools.stringToBCDNString(dn17), "CN=foo,CN=bar,O=CN,O=C,C=CN");

        String dn18 = "cn=jean,cn=EJBCA,dc=home,dc=jean";
        assertEquals(CertTools.stringToBCDNString(dn18), "CN=jean,CN=EJBCA,DC=home,DC=jean");

        String dn19 = "cn=bar, cn=foo,o=oo, O=EJBCA,DC=DC2, dc=dc1, C=SE";
        assertEquals(CertTools.stringToBCDNString(dn19), "CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE");

        String dn20 = " CN=\"foo, OU=bar\",  O=baz\\\\\\, quux,C=SE ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals(CertTools.stringToBCDNString(dn20), "CN=foo\\, OU=bar,O=baz\\\\\\, quux,C=SE");

        String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
        String bcdn21 = CertTools.stringToBCDNString(dn21);
        assertEquals(bcdn21, "CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");
        // it is allowed to escape ,
        assertEquals(StringTools.strip(bcdn21), "CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE");

        String dn22 = "C=SE,O=Foo\\, Inc, OU=Foo, Dep, CN=Foo'";
        String bcdn22 = CertTools.stringToBCDNString(dn22);
        assertEquals(bcdn22, "CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");
        assertEquals(StringTools.strip(bcdn22), "CN=Foo',OU=Foo,O=Foo\\, Inc,C=SE");
        log.debug("<test02StringToBCDNString()");
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void test03AltNames() throws Exception {
        log.debug(">test03AltNames()");

        // We try to examine the general case and som special cases, which we want to be able to handle
        String alt1 = "rfc822Name=ejbca@primekey.se, dNSName=www.primekey.se, uri=http://www.primekey.se/ejbca";
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.EMAIL), "ejbca@primekey.se");
        assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL1));
        assertNull(CertTools.getPartFromDN(alt1, CertTools.EMAIL2));
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.DNS), "www.primekey.se");
        assertNull(CertTools.getPartFromDN(alt1, CertTools.URI));
        assertEquals(CertTools.getPartFromDN(alt1, CertTools.URI1), "http://www.primekey.se/ejbca");

        String alt2 = "email=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(CertTools.getPartFromDN(alt2, CertTools.EMAIL1), "ejbca@primekey.se");
        assertEquals(CertTools.getPartFromDN(alt2, CertTools.URI), "http://www.primekey.se/ejbca");

        String alt3 = "EmailAddress=ejbca@primekey.se, dNSName=www.primekey.se, uniformResourceIdentifier=http://www.primekey.se/ejbca";
        assertEquals(CertTools.getPartFromDN(alt3, CertTools.EMAIL2), "ejbca@primekey.se");

        X509Certificate cert = CertTools.getCertfromByteArray(guidcert);
        String upn = CertTools.getUPNAltName(cert);
        assertEquals(upn, "guid@foo.com");
        String guid = CertTools.getGuidAltName(cert);
        assertEquals(guid, "1234567890abcdef");
        log.debug("<test03AltNames()");
    }

    /**
     * DOCUMENT ME!
     *
     * @throws Exception DOCUMENT ME!
     */
    public void test04DNComponents() throws Exception {
        log.debug(">test04DNComponents()");

        // We try to examine the general case and som special cases, which we want to be able to handle
        String dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals(bcdn1,
                "CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE");
        log.debug("<test04DNComponents()");
    }

    /** Tests string coding/decoding international (swedish characters)
     *
     * @throws Exception if error...
     */
    public void test05IntlChars() throws Exception {
        log.debug(">test05IntlChars()");
        // We try to examine the general case and som special cases, which we want to be able to handle
        String dn1 = "CN=Tomas?????????, O=?????????-Org, OU=??????-Unit, C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("CN=Tomas?????????,OU=??????-Unit,O=?????????-Org,C=SE", bcdn1);
        log.debug("<test05IntlChars()");
    }

    /** Tests some of the other methods of CertTools
     *
     * @throws Exception if error...
     */
    public void test06CertOps() throws Exception {
        log.debug(">test06CertOps()");
        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        X509Certificate gcert = CertTools.getCertfromByteArray(guidcert);
        assertEquals("Wrong issuerDN", CertTools.getIssuerDN(cert), CertTools.stringToBCDNString("CN=TestCA,O=AnaTom,C=SE"));
        assertEquals("Wrong subjectDN", CertTools.getSubjectDN(cert), CertTools.stringToBCDNString("CN=p12test,O=PrimeTest,C=SE"));
        assertEquals("Wrong subject key id", new String(Hex.encode(CertTools.getSubjectKeyId(cert))), "E74F5690F48D147783847CD26448E8094ABB08A0".toLowerCase());
        assertEquals("Wrong authority key id", new String(Hex.encode(CertTools.getAuthorityKeyId(cert))), "637BF476A854248EA574A57744A6F45E0F579251".toLowerCase());
        assertEquals("Wrong upn alt name", "foo@foo", CertTools.getUPNAltName(cert));
        assertEquals("Wrong guid alt name", "1234567890abcdef", CertTools.getGuidAltName(gcert));
        assertEquals("Wrong certificate policy", "1.1.1.1.1.1", CertTools.getCertificatePolicyId(cert, 0));
        assertNull("Not null policy", CertTools.getCertificatePolicyId(cert, 1));
//        System.out.println(cert);
//        FileOutputStream fos = new FileOutputStream("foo.cert");
//        fos.write(cert.getEncoded());
//        fos.close();
        log.debug("<test06CertOps()");
    }

    /** Tests the handling of DC components
     *
     * @throws Exception if error...
     */
    public void test07TestDC() throws Exception {
        log.debug(">test07TestDC()");
        // We try to examine the that we handle modern dc components for ldap correctly
        String dn1 = "dc=bigcorp,dc=com,dc=se,ou=users,cn=Mike Jackson";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        //assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com", bcdn1);
        String dn2 = "cn=Mike Jackson,ou=users,dc=se,dc=bigcorp,dc=com";
        String bcdn2 = CertTools.stringToBCDNString(dn2);
        log.debug("dn2: " + dn2);
        log.debug("bcdn2: " + bcdn2);
        assertEquals("CN=Mike Jackson,OU=users,DC=se,DC=bigcorp,DC=com", bcdn2);
        log.debug("<test07TestDC()");
    }

    /** Tests the handling of unstructuredName/Address
     *
     * @throws Exception if error...
     */
    public void test08TestUnstructured() throws Exception {
        log.debug(">test08TestUnstructured()");
        // We try to examine the that we handle modern dc components for ldap correctly
        String dn1 = "C=SE,O=PrimeKey,unstructuredName=10.1.1.2,unstructuredAddress=foo.bar.se,cn=test";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: " + dn1);
        log.debug("bcdn1: " + bcdn1);
        assertEquals("unstructuredAddress=foo.bar.se,unstructuredName=10.1.1.2,CN=test,O=PrimeKey,C=SE", bcdn1);
        log.debug("<test08TestUnstructured()");
    }

    /** Tests the reversing of a DN
    *
    * @throws Exception if error...
    */
   public void test09TestReverse() throws Exception {
       log.debug(">test09TestReverse()");
       // We try to examine the that we handle modern dc components for ldap correctly
       String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
       String dn2 = "cn=Tomas G,ou=users,ou=orgunit,dc=se,dc=bigcorp,dc=com";
       assertTrue(CertTools.isDNReversed(dn1));
       assertTrue(!CertTools.isDNReversed(dn2));
       assertTrue(CertTools.isDNReversed("C=SE,CN=Foo"));
       assertTrue(!CertTools.isDNReversed("CN=Foo,O=FooO"));
       String revdn1 = CertTools.reverseDN(dn1);
       log.debug("dn1: " + dn1);
       log.debug("revdn1: " + revdn1);
       assertEquals(dn2, revdn1);
       
       log.debug("<test09TestReverse()");
   }
    /** Tests the handling of DC components
    *
    * @throws Exception if error...
    */
   public void test10TestMultipleReversed() throws Exception {
       log.debug(">test10TestMultipleReversed()");
       // We try to examine the that we handle modern dc components for ldap correctly
       String dn1 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G";
       String bcdn1 = CertTools.stringToBCDNString(dn1);
       log.debug("dn1: " + dn1);
       log.debug("bcdn1: " + bcdn1);
       assertEquals("CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", bcdn1);

       String dn19 = "C=SE, dc=dc1,DC=DC2,O=EJBCA, O=oo, cn=foo, cn=bar";
       assertEquals("CN=bar,CN=foo,O=oo,O=EJBCA,DC=DC2,DC=dc1,C=SE", CertTools.stringToBCDNString(dn19));
       String dn20 = " C=SE,CN=\"foo, OU=bar\",  O=baz\\\\\\, quux  ";
       // BC always escapes with backslash, it doesn't use quotes.
       assertEquals("CN=foo\\, OU=bar,O=baz\\\\\\, quux,C=SE", CertTools.stringToBCDNString(dn20));

       String dn21 = "C=SE,O=Foo\\, Inc, OU=Foo\\, Dep, CN=Foo\\'";
       String bcdn21 = CertTools.stringToBCDNString(dn21);
       assertEquals("CN=Foo\',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", bcdn21);        
       assertEquals("CN=Foo',OU=Foo\\, Dep,O=Foo\\, Inc,C=SE", StringTools.strip(bcdn21));        
       log.debug("<test10TestMultipleReversed()");
   }
   
   /** Tests the insertCNPostfix function
   *
   * @throws Exception if error...
   */
  public void test11TestInsertCNPostfix() throws Exception {
      log.debug(">test11TestInsertCNPostfix()");
      
      // Test the regular case with one CN beging replaced with " (VPN)" postfix
      String dn1 = "CN=Tomas G,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
      String cnpostfix1 = " (VPN)";      
      String newdn1 = CertTools.insertCNPostfix(dn1,cnpostfix1);
      assertEquals("CN=Tomas G (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn1);
      
      // Test case when CN doesn't exist
      String dn2 = "OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
      String newdn2 = CertTools.insertCNPostfix(dn2,cnpostfix1); 
      assertEquals("OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn2);
      
      // Test case with two CNs in DN only first one should be replaced.
      String dn3 = "CN=Tomas G,CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";  
      String newdn3 = CertTools.insertCNPostfix(dn3,cnpostfix1); 
      assertEquals("CN=Tomas G (VPN),CN=Bagare,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn3);
 
      // Test case with two CNs in reversed DN 
      String dn4 = "dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G,CN=Bagare";
      String newdn4 = CertTools.insertCNPostfix(dn4,cnpostfix1); 
      assertEquals("dc=com,dc=bigcorp,dc=se,ou=orgunit,ou=users,cn=Tomas G (VPN),CN=Bagare", newdn4);

      // Test case with two CNs in reversed DN 
      String dn5 = "UID=tomas,CN=tomas,OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com";
      String cnpostfix5 = " (VPN)";      
      String newdn5 = CertTools.insertCNPostfix(dn5,cnpostfix5);
      assertEquals("UID=tomas,CN=tomas (VPN),OU=users,OU=orgunit,DC=se,DC=bigcorp,DC=com", newdn5);
      
      log.debug("<test11TestInsertCNPostfix()");
  }
  
  /**
   */
  public void test12GetPartsFromDN() throws Exception {
      log.debug(">test01GetPartFromDN()");

      // We try to examine the general case and som special cases, which we want to be able to handle
      String dn0 = "C=SE, O=AnaTom, CN=foo";
      assertEquals(CertTools.getPartsFromDN(dn0, "CN").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "CN").contains("foo"));
      assertEquals(CertTools.getPartsFromDN(dn0, "O").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "O").contains("AnaTom"));
      assertEquals(CertTools.getPartsFromDN(dn0, "C").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "C").contains("SE"));
      assertEquals(CertTools.getPartsFromDN(dn0, "cn").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "cn").contains("foo"));
      assertEquals(CertTools.getPartsFromDN(dn0, "o").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "o").contains("AnaTom"));
      assertEquals(CertTools.getPartsFromDN(dn0, "c").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn0, "c").contains("SE"));

      String dn1 = "uri=http://www.a.se, C=SE, O=AnaTom, CN=foo";
      assertEquals(CertTools.getPartsFromDN(dn1, "CN").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn1, "CN").contains("foo"));
      assertEquals(CertTools.getPartsFromDN(dn1, CertTools.URI).size(), 0);
      assertEquals(CertTools.getPartsFromDN(dn1, CertTools.URI1).size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn1, CertTools.URI1).contains("http://www.a.se"));

      String dn2 = "uri=http://www.a.se, uri=http://www.b.se, C=SE, O=AnaTom, CN=foo";
      assertEquals(CertTools.getPartsFromDN(dn2, "CN").size(), 1);
      assertTrue(CertTools.getPartsFromDN(dn2, "CN").contains("foo"));
      assertEquals(CertTools.getPartsFromDN(dn2, CertTools.URI1).size(), 2);
      assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains("http://www.a.se"));
      assertTrue(CertTools.getPartsFromDN(dn2, CertTools.URI1).contains("http://www.b.se"));

      log.debug("<test12GetPartsFromDN()");
  }
  
  public void test13GetSubjectAltNameString() throws Exception {
      log.debug(">test13GetSubjectAltNameString()");
      
      String altNames = CertTools.getSubjectAlternativeName(CertTools.getCertfromByteArray(altNameCert));
      log.debug(altNames);
      String name = CertTools.getPartFromDN(altNames,CertTools.UPN);
      assertEquals("foo@a.se", name);
      assertEquals("foo@a.se", CertTools.getUPNAltName(CertTools.getCertfromByteArray(altNameCert)));
      name = CertTools.getPartFromDN(altNames,CertTools.URI);
      assertEquals("http://www.a.se/", name);
      name = CertTools.getPartFromDN(altNames,CertTools.EMAIL);
      assertEquals("tomas@a.se", name);
      name = CertTools.getEMailAddress(CertTools.getCertfromByteArray(altNameCert));
      assertEquals("tomas@a.se", name);
      name = CertTools.getEMailAddress(CertTools.getCertfromByteArray(testcert));
      assertNull(name);
      name = CertTools.getPartFromDN(altNames,CertTools.DNS);
      assertEquals("www.a.se", name);
      name = CertTools.getPartFromDN(altNames,CertTools.IPADDR);
      assertEquals("10.1.1.1", name);
      log.debug("<test13GetSubjectAltNameString()");
  }

}
