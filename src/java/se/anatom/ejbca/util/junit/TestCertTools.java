package se.anatom.ejbca.util.junit;

import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.*;

import org.apache.log4j.Logger;
import junit.framework.*;

/**
 * Tests the CertTools class .
 *
 * @version $Id: TestCertTools.java,v 1.9 2003-04-03 14:59:26 anatom Exp $
 */
public class TestCertTools extends TestCase {

    private static Logger log = Logger.getLogger(TestCertTools.class);

    static byte[] testcert = Base64.decode(
    ("MIICmjCCAgOgAwIBAgIIFKDXpk/2g0kwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
    +"AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDMz"
    +"MTA4NTQxMVoXDTA1MDMzMDA5MDQxMVowKTEMMAoGA1UEAxMDdXBuMQwwCgYDVQQK"
    +"EwNGb28xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCP"
    +"d6lpi+MaIr+f+tnlWfYqE6OMP24H0JlQxPoLqV2ElX2Yk00fHchicl6wPYxEwIhQ"
    +"PMX7oP/j04gpLf3YuY47aajo/Nruibot+waIi+xWHZ0zONYgRnRez1DfWDPsmh5/"
    +"6LS7jTe9A9FaU7Q3QVZ0iYy8zQsIDR+tL1A5jK6UmQIBEaOBxjCBwzAPBgNVHRMB"
    +"Af8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQwMgYIKwYBBQUHAwEG"
    +"CCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUFBwMHMB0GA1UdDgQW"
    +"BBRqt8tdCpOtaXxKyQHpdSvoTYGZIjAfBgNVHSMEGDAWgBRje/R2qFQkjqV0pXdE"
    +"pvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwHZm9vQGZvbzANBgkq"
    +"hkiG9w0BAQUFAAOBgQBc4zx+poGoO/5UdbcycL7YsU3a4fSxYfxkxBapRhsiC29a"
    +"mr7aZJAjcrB9aEKgZWBQbvfM5TrmFbTKJExnmtWovBuLjxESQ0+v7LtJeSbpdqnd"
    +"KASddFTjB6H1cweKOL64o+ZVYjfWQKXN/gG9Sd+fAb9zc5jKU5fT/NBvBgRfdg==").getBytes());

    public TestCertTools(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        log.debug("<setUp()");

    }
    protected void tearDown() throws Exception {
    }

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
        String dn19 = "C=SE, dc=dc1,DC=DC2,O=EJBCA, O=oo, cn=foo, cn=bar";
        assertEquals(CertTools.stringToBCDNString(dn19), "CN=foo,CN=bar,O=EJBCA,O=oo,DC=dc1,DC=DC2,C=SE");
        String dn20 = " C=SE,CN=\"foo, OU=bar\",  O=baz\\\\\\, quux  ";
        // BC always escapes with backslash, it doesn't use quotes.
        assertEquals(CertTools.stringToBCDNString(dn20), "CN=foo\\, OU=bar,O=baz\\\\\\, quux,C=SE");

        log.debug("<test02StringToBCDNString()");
    }

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

        X509Certificate cert = CertTools.getCertfromByteArray(testcert);
        String upn = CertTools.getUPNAltName(cert);
        log.debug("UPN="+upn);
        assertEquals(upn,"foo@foo");
        log.debug("<test03AltNames()");
    }

    public void test04DNComponents() throws Exception {
        log.debug(">test04DNComponents()");

        // We try to examine the general case and som special cases, which we want to be able to handle
        String dn1 = "CN=CommonName, O=Org, OU=OrgUnit, SerialNumber=SerialNumber, SurName=SurName, GivenName=GivenName, Initials=Initials, C=SE";
        String bcdn1 = CertTools.stringToBCDNString(dn1);
        log.debug("dn1: "+dn1);
        log.debug("bcdn1: "+bcdn1);
        assertEquals(bcdn1, "CN=CommonName,SN=SerialNumber,GIVENNAME=GivenName,INITIALS=Initials,SURNAME=SurName,OU=OrgUnit,O=Org,C=SE");
        log.debug("<test04DNComponents()");
    }

}
