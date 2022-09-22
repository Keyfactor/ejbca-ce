/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificates;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.junit.Test;

/**
 *
 */
public class CrlToolsTest {

    private static final Logger log = Logger.getLogger(CrlToolsTest.class);

    private static byte[] testcrl = Base64.decode(("MIHGMHICAQEwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEVEVTVBcNMTEwMTMx"
            +"MTMzOTE3WhcNMTEwMTMxMTMzOTE3WqAvMC0wHwYDVR0jBBgwFoAUt39s38+I8fP0"
            +"diUs8Y8TYtCar8gwCgYDVR0UBAMCAQEwDQYJKoZIhvcNAQELBQADQQBcr4CF0sy3"
            +"5sVvEafzh67itIasqcv/PwUT6DwQxoiX85h53cFtvXQxi/2Xqn+PaNBOqWShByX7"
            +"TQlMX0Bmoz9/").getBytes());

    private static byte[] testdeltacrl = Base64.decode(("MIHWMIGBAgEBMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBFRFU1QXDTExMDEz"
            +"MTEzNDcxOFoXDTExMDEzMTEzNDcxOFqgPjA8MB8GA1UdIwQYMBaAFJ5BHYGqJr3K"
            +"j9IMQxmMP6ad8gDdMAoGA1UdFAQDAgEDMA0GA1UdGwEB/wQDAgECMA0GCSqGSIb3"
            +"DQEBCwUAA0EAP8CIPLll5m/wmhcLL5SXlb+aYrPGsUlBFNBKYKO0iV1QjBHeDMp5"
            +"z70nU3g2tIfiEX4IKNFyzFvn5m6e8m0JQQ==").getBytes());

    private static byte[] testCrlWithIssuingDistributionPoint = Base64.decode(("MIIBTjCBrwIBATALBglghkgBZQMEAwswHTEbMBkGA1UEAwwSQ0Egd0l0aCBJRFAgb24gQ1JMFw0x\n" + 
            "OTAzMjExOTM1MzhaFw0xOTAzMjIxOTM1MzhaoGAwXjAfBgNVHSMEGDAWgBRv8z/8lQ2y+HtRbGYD\n" + 
            "y+BFdDPGwjAKBgNVHRQEAwIBBTAvBgNVHRwBAf8EJTAjoCGgH4YdaHR0cDovL2NybC5leGFtcGxl\n" + 
            "LmNvbS9DQS5jcmwwCwYJYIZIAWUDBAMLA4GMADCBiAJCARTNuZfLD+sm/UXPjlcycSjX1cPv4kpV\n" + 
            "Z3YYTPQPLl+zDe+J2mtkTEVeaL8J/Jg5o3i+RKtjUVVQ9P8CidlpecCPAkIBL3KbYAz4OOI+GVIY\n" + 
            "CmYzteNakXsgEtyvZVGRr8lGlH1dCVcuFq46bqalHDp77+H5sVczATYSYVAUjxyAqvBLcOY=").getBytes());
    
    /** Cert with CDP without URI. */
    /*
     * Cert with CDP without URI. <pre> Certificate: Data: Version: 3 (0x2) Serial Number: 1042070824 (0x3e1cbd28) Signature Algorithm:
     * sha1WithRSAEncryption Issuer: C=US, O=Adobe Systems Incorporated, OU=Adobe Trust Services, CN=Adobe Root CA Validity Not Before: Jan 8 23:37:23
     * 2003 GMT Not After : Jan 9 00:07:23 2023 GMT Subject: C=US, O=Adobe Systems Incorporated, OU=Adobe Trust Services, CN=Adobe Root CA Subject
     * Public Key Info: Public Key Algorithm: rsaEncryption RSA Public Key: (2048 bit) Modulus (2048 bit):
     * 00:cc:4f:54:84:f7:a7:a2:e7:33:53:7f:3f:9c:12: 88:6b:2c:99:47:67:7e:0f:1e:b9:ad:14:88:f9:c3: 10:d8:1d:f0:f0:d5:9f:69:0a:2f:59:35:b0:cc:6c:
     * a9:4c:9c:15:a0:9f:ce:20:bf:a0:cf:54:e2:e0:20: 66:45:3f:39:86:38:7e:9c:c4:8e:07:22:c6:24:f6: 01:12:b0:35:df:55:ea:69:90:b0:db:85:37:1e:e2:
     * 4e:07:b2:42:a1:6a:13:69:a0:66:ea:80:91:11:59: 2a:9b:08:79:5a:20:44:2d:c9:bd:73:38:8b:3c:2f: e0:43:1b:5d:b3:0b:f0:af:35:1a:29:fe:ef:a6:92:
     * dd:81:4c:9d:3d:59:8e:ad:31:3c:40:7e:9b:91:36: 06:fc:e2:5c:8d:d1:8d:26:d5:5c:45:cf:af:65:3f: b1:aa:d2:62:96:f4:a8:38:ea:ba:60:42:f4:f4:1c:
     * 4a:35:15:ce:f8:4e:22:56:0f:95:18:c5:f8:96:9f: 9f:fb:b0:b7:78:25:e9:80:6b:bd:d6:0a:f0:c6:74: 94:9d:f3:0f:50:db:9a:77:ce:4b:70:83:23:8d:a0:
     * ca:78:20:44:5c:3c:54:64:f1:ea:a2:30:19:9f:ea: 4c:06:4d:06:78:4b:5e:92:df:22:d2:c9:67:b3:7a: d2:01 Exponent: 65537 (0x10001) X509v3 extensions:
     * Netscape Cert Type: SSL CA, S/MIME CA, Object Signing CA X509v3 CRL Distribution Points: DirName:/C=US/O=Adobe Systems Incorporated/OU=Adobe
     * Trust Services/CN=Adobe Root CA/CN=CRL1
     * 
     * X509v3 Private Key Usage Period: Not Before: Jan 8 23:37:23 2003 GMT, Not After: Jan 9 00:07:23 2023 GMT X509v3 Key Usage: Certificate Sign,
     * CRL Sign X509v3 Authority Key Identifier: keyid:82:B7:38:4A:93:AA:9B:10:EF:80:BB:D9:54:E2:F1:0F:FB:80:9C:DE
     * 
     * X509v3 Subject Key Identifier: 82:B7:38:4A:93:AA:9B:10:EF:80:BB:D9:54:E2:F1:0F:FB:80:9C:DE X509v3 Basic Constraints: CA:TRUE
     * 1.2.840.113533.7.65.0: 0...V6.0:4.0.... Signature Algorithm: sha1WithRSAEncryption 32:da:9f:43:75:c1:fa:6f:c9:6f:db:ab:1d:36:37:3e:bc:61:
     * 19:36:b7:02:3c:1d:23:59:98:6c:9e:ee:4d:85:e7:54:c8:20: 1f:a7:d4:bb:e2:bf:00:77:7d:24:6b:70:2f:5c:c1:3a:76:49:
     * b5:d3:e0:23:84:2a:71:6a:22:f3:c1:27:29:98:15:f6:35:90: e4:04:4c:c3:8d:bc:9f:61:1c:e7:fd:24:8c:d1:44:43:8c:16:
     * ba:9b:4d:a5:d4:35:2f:bc:11:ce:bd:f7:51:37:8d:9f:90:e4: 14:f1:18:3f:be:e9:59:12:35:f9:33:92:f3:9e:e0:d5:6b:9a:
     * 71:9b:99:4b:c8:71:c3:e1:b1:61:09:c4:e5:fa:91:f0:42:3a: 37:7d:34:f9:72:e8:cd:aa:62:1c:21:e9:d5:f4:82:10:e3:7b:
     * 05:b6:2d:68:56:0b:7e:7e:92:2c:6f:4d:72:82:0c:ed:56:74: b2:9d:b9:ab:2d:2b:1d:10:5f:db:27:75:70:8f:fd:1d:d7:e2:
     * 02:a0:79:e5:1c:e5:ff:af:64:40:51:2d:9e:9b:47:db:42:a5: 7c:1f:c2:a6:48:b0:d7:be:92:69:4d:a4:f6:29:57:c5:78:11:
     * 18:dc:87:51:ca:13:b2:62:9d:4f:2b:32:bd:31:a5:c1:fa:52: ab:05:88:c8 </pre>
     */
    private static final String CERT_WITHOUT_URI = "-----BEGIN CERTIFICATE-----\n"
            + "MIIEoTCCA4mgAwIBAgIEPhy9KDANBgkqhkiG9w0BAQUFADBpMQswCQYDVQQGEwJV" + "UzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0ZWQxHTAbBgNVBAsT"
            + "FEFkb2JlIFRydXN0IFNlcnZpY2VzMRYwFAYDVQQDEw1BZG9iZSBSb290IENBMB4X" + "DTAzMDEwODIzMzcyM1oXDTIzMDEwOTAwMDcyM1owaTELMAkGA1UEBhMCVVMxIzAh"
            + "BgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVkMR0wGwYDVQQLExRBZG9i" + "ZSBUcnVzdCBTZXJ2aWNlczEWMBQGA1UEAxMNQWRvYmUgUm9vdCBDQTCCASIwDQYJ"
            + "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMxPVIT3p6LnM1N/P5wSiGssmUdnfg8e" + "ua0UiPnDENgd8PDVn2kKL1k1sMxsqUycFaCfziC/oM9U4uAgZkU/OYY4fpzEjgci"
            + "xiT2ARKwNd9V6mmQsNuFNx7iTgeyQqFqE2mgZuqAkRFZKpsIeVogRC3JvXM4izwv" + "4EMbXbML8K81Gin+76aS3YFMnT1Zjq0xPEB+m5E2BvziXI3RjSbVXEXPr2U/sarS"
            + "Ypb0qDjqumBC9PQcSjUVzvhOIlYPlRjF+Jafn/uwt3gl6YBrvdYK8MZ0lJ3zD1Db" + "mnfOS3CDI42gynggRFw8VGTx6qIwGZ/qTAZNBnhLXpLfItLJZ7N60gECAwEAAaOC"
            + "AU8wggFLMBEGCWCGSAGG+EIBAQQEAwIABzCBjgYDVR0fBIGGMIGDMIGAoH6gfKR6" + "MHgxCzAJBgNVBAYTAlVTMSMwIQYDVQQKExpBZG9iZSBTeXN0ZW1zIEluY29ycG9y"
            + "YXRlZDEdMBsGA1UECxMUQWRvYmUgVHJ1c3QgU2VydmljZXMxFjAUBgNVBAMTDUFk" + "b2JlIFJvb3QgQ0ExDTALBgNVBAMTBENSTDEwKwYDVR0QBCQwIoAPMjAwMzAxMDgy"
            + "MzM3MjNagQ8yMDIzMDEwOTAwMDcyM1owCwYDVR0PBAQDAgEGMB8GA1UdIwQYMBaA" + "FIK3OEqTqpsQ74C72VTi8Q/7gJzeMB0GA1UdDgQWBBSCtzhKk6qbEO+Au9lU4vEP"
            + "+4Cc3jAMBgNVHRMEBTADAQH/MB0GCSqGSIb2fQdBAAQQMA4bCFY2LjA6NC4wAwIE" + "kDANBgkqhkiG9w0BAQUFAAOCAQEAMtqfQ3XB+m/Jb9urHTY3PrxhGTa3AjwdI1mY"
            + "bJ7uTYXnVMggH6fUu+K/AHd9JGtwL1zBOnZJtdPgI4QqcWoi88EnKZgV9jWQ5ARM" + "w428n2Ec5/0kjNFEQ4wWuptNpdQ1L7wRzr33UTeNn5DkFPEYP77pWRI1+TOS857g"
            + "1WuacZuZS8hxw+GxYQnE5fqR8EI6N300+XLozapiHCHp1fSCEON7BbYtaFYLfn6S" + "LG9NcoIM7VZ0sp25qy0rHRBf2yd1cI/9HdfiAqB55Rzl/69kQFEtnptH20KlfB/C"
            + "pkiw176SaU2k9ilXxXgRGNyHUcoTsmKdTysyvTGlwfpSqwWIyA==" + "\n-----END CERTIFICATE-----";
    
    /** Cert with CDP with URI */
    /*
     * Cert with CDP with URI. <pre> Certificate: Data: Version: 3 (0x2) Serial Number: 52:32:6f:be:9d:3c:4d:d7 Signature Algorithm:
     * sha1WithRSAEncryption Issuer: CN=DemoSubCA11, O=Demo Organization 10, C=SE Validity Not Before: Apr 3 22:17:41 2010 GMT Not After : Apr 2
     * 22:17:41 2012 GMT Subject: CN=pdfsigner12-2testcrl-with-subca Subject Public Key Info: Public Key Algorithm: rsaEncryption RSA Public Key:
     * (1024 bit) Modulus (1024 bit): 00:de:99:da:80:ad:03:21:3c:18:cc:41:1f:ad:4a: fc:2d:69:21:3d:34:52:7c:a4:9c:33:df:a8:36:5a:
     * ee:bd:74:f6:0b:b1:93:79:3c:e7:66:a1:72:d4:1f: 08:b6:43:a3:0a:1a:94:8c:64:e4:10:71:32:be:4b: 00:08:a3:25:11:85:2a:d3:af:fa:dc:d4:ac:7a:48:
     * e8:d3:63:d0:06:4a:cf:ce:84:0e:a5:88:6e:1f:44: c1:9f:ad:89:1e:8b:d0:17:53:20:40:b5:e9:b3:7d: 16:74:e0:22:a7:43:44:99:6a:ba:5c:26:ed:f8:c7:
     * 8c:a5:14:a2:40:83:d6:52:75 Exponent: 65537 (0x10001) X509v3 extensions: X509v3 Subject Key Identifier:
     * 8F:23:26:05:9D:03:57:4F:66:08:F5:E3:34:D3:AA:70:76:9C:99:B2 X509v3 Basic Constraints: critical CA:FALSE X509v3 Authority Key Identifier:
     * keyid:90:FD:A7:F6:EC:98:47:56:4C:10:96:C2:AD:85:2F:50:EB:26:E9:34
     * 
     * X509v3 CRL Distribution Points:
     * URI:http://vmserver1:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=DemoSubCA11,O=Demo%20Organization%2010,C=SE
     * 
     * X509v3 Key Usage: critical Digital Signature Signature Algorithm: sha1WithRSAEncryption 6e:f0:b9:26:b8:7d:eb:b2:ab:ec:e7:1b:a5:97:5c:5b:88:fe:
     * 8a:ec:bb:3d:7a:f5:00:4c:72:38:36:19:53:d4:47:21:30:4c: 62:7c:02:69:00:8c:ac:57:3c:f2:bf:38:57:13:0b:4b:7e:92:
     * 74:56:4c:1b:9c:04:9d:08:e8:8e:20:4d:bc:ec:bc:13:c7:55: 80:da:1a:01:9f:9f:be:96:11:d4:7c:64:f2:37:91:01:9f:c0:
     * 91:af:b6:8a:62:80:71:75:e6:34:f5:57:85:79:d8:7d:e3:71: 71:fa:7c:ca:c8:03:13:d5:0c:12:f5:f6:27:29:36:99:e4:ec: 8b:b1 </pre>
     */
    private static final String CERT_WITH_URI = "-----BEGIN CERTIFICATE-----\n" + "MIIC0zCCAjygAwIBAgIIUjJvvp08TdcwDQYJKoZIhvcNAQEFBQAwQjEUMBIGA1UE"
            + "AwwLRGVtb1N1YkNBMTExHTAbBgNVBAoMFERlbW8gT3JnYW5pemF0aW9uIDEwMQsw" + "CQYDVQQGEwJTRTAeFw0xMDA0MDMyMjE3NDFaFw0xMjA0MDIyMjE3NDFaMCoxKDAm"
            + "BgNVBAMMH3BkZnNpZ25lcjEyLTJ0ZXN0Y3JsLXdpdGgtc3ViY2EwgZ8wDQYJKoZI" + "hvcNAQEBBQADgY0AMIGJAoGBAN6Z2oCtAyE8GMxBH61K/C1pIT00UnyknDPfqDZa"
            + "7r109guxk3k852ahctQfCLZDowoalIxk5BBxMr5LAAijJRGFKtOv+tzUrHpI6NNj" + "0AZKz86EDqWIbh9EwZ+tiR6L0BdTIEC16bN9FnTgIqdDRJlqulwm7fjHjKUUokCD"
            + "1lJ1AgMBAAGjgekwgeYwHQYDVR0OBBYEFI8jJgWdA1dPZgj14zTTqnB2nJmyMAwG" + "A1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUkP2n9uyYR1ZMEJbCrYUvUOsm6TQwgYUG"
            + "A1UdHwR+MHwweqB4oHaGdGh0dHA6Ly92bXNlcnZlcjE6ODA4MC9lamJjYS9wdWJs" + "aWN3ZWIvd2ViZGlzdC9jZXJ0ZGlzdD9jbWQ9Y3JsJmlzc3Vlcj1DTj1EZW1vU3Vi"
            + "Q0ExMSxPPURlbW8lMjBPcmdhbml6YXRpb24lMjAxMCxDPVNFMA4GA1UdDwEB/wQE" + "AwIHgDANBgkqhkiG9w0BAQUFAAOBgQBu8LkmuH3rsqvs5xull1xbiP6K7Ls9evUA"
            + "THI4NhlT1EchMExifAJpAIysVzzyvzhXEwtLfpJ0VkwbnASdCOiOIE287LwTx1WA" + "2hoBn5++lhHUfGTyN5EBn8CRr7aKYoBxdeY09VeFedh943Fx+nzKyAMT1QwS9fYn"
            + "KTaZ5OyLsQ==" + "\n-----END CERTIFICATE-----";
    
    @Test
    public void getCrlDistributionPointForCrl() throws Exception {
        Collection<String> uris;
        // CRL without IDP
        X509CRL crl = CrlTools.getCRLfromByteArray(testcrl);
        uris = CrlTools.getCrlDistributionPoints(crl);
        assertEquals("Should return no URIs for CRL without issuingDistributionPoint.", 0, uris.size());
        // CRL with IDP
        crl = CrlTools.getCRLfromByteArray(testCrlWithIssuingDistributionPoint);
        uris = CrlTools.getCrlDistributionPoints(crl);
        assertEquals("Should return IDP URL for CRL with issuingDistributionPoint.", 1, uris.size());
        assertEquals("Extracted string from issuingDistributionPoint is wrong.", "http://crl.example.com/CA.crl", uris.iterator().next());
    }
    
    @Test
    public void testGetCrlAuthorityKeyId() throws Exception {
        final X509CRL crl = CrlTools.getCRLfromByteArray(testcrl);
        final byte[] authorityKeyIdBytes = CrlTools.getAuthorityKeyId(crl);
        final String authorityKeyId = new String(Hex.encode(authorityKeyIdBytes));
        assertEquals("Unexpected Authorirt Key Id returned", "b77f6cdfcf88f1f3f476252cf18f1362d09aafc8", authorityKeyId);
    }
    
    @Test
    public void testCRLs() throws Exception {
        X509CRL crl = CrlTools.getCRLfromByteArray(testcrl);
        assertEquals("CN=TEST", CrlTools.getIssuerDN(crl));
        byte[] pembytes = CrlTools.getPEMFromCrl(testcrl);
        String pem = new String(pembytes);
        assertTrue(pem.contains("BEGIN X509 CRL"));
        assertEquals(1, CrlExtensions.getCrlNumber(crl).intValue());
        assertEquals(-1, CrlExtensions.getDeltaCRLIndicator(crl).intValue());

        X509CRL deltacrl = CrlTools.getCRLfromByteArray(testdeltacrl);
        assertEquals(3, CrlExtensions.getCrlNumber(deltacrl).intValue());
        assertEquals(2, CrlExtensions.getDeltaCRLIndicator(deltacrl).intValue());

    }
    
    @Test
    public void testGetCrlDistributionPoint() throws Exception {
        Collection<X509Certificate> certs;
        String url;
        // Test with normal cert
        certs = X509CertificateTools.getCertsFromPEM(new ByteArrayInputStream(CERT_WITH_URI.getBytes()));
        url = CrlTools.getCrlDistributionPoint(certs.iterator().next());
        assertNotNull(url);
        assertEquals("Wrong CRL Distribution Point.", "http://vmserver1:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=DemoSubCA11,O=Demo%20Organization%2010,C=SE", url);
        // Test with cert that contains CDP without URI
        certs = X509CertificateTools.getCertsFromPEM(new ByteArrayInputStream(CERT_WITHOUT_URI.getBytes()));
        url = CrlTools.getCrlDistributionPoint(certs.iterator().next());
        assertNull(url); 
    }

}
