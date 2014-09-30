/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CertTools class .
 * 
 * @version $Id$
 */
public class KeyToolsTest {

    private static Logger log = Logger.getLogger(KeyToolsTest.class);

    private static final byte[] ks3 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAyYwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "DjCCAwowggMGBgsqhkiG9w0BDAoBAqCCAqkwggKlMCcGCiqGSIb3DQEMAQMwGQQU" + "/h0pQXq7ZVjYWlDvzEwwmiJ8O8oCAWQEggJ4MZ12+kTVGd1w7SP4ZWlq0bCc4MsJ"
            + "O0FFSX3xeVp8Bx16io1WkEFOW3xfqjuxKOL6YN9atoOZdfhlOMhmbhglm2PJSzIg" + "JSDHvWk2xKels5vh4hY1iXWOh48077Us4wP4Qt94iKglCq4xwxYcSCW8BJwbu93F"
            + "uxE1twnWXbH192nMhaeIAy0v4COdduQamJEtHRmIJ4GZwIhH+lNHj/ARdIfNw0Dm" + "uPspuSu7rh6rQ8SrRsjg63EoxfSH4Lz6zIJKF0OjNX07T8TetFgznCdGCrqOZ1fK"
            + "5oRzXIA9hi6UICiuLSm4EoHzEpifCObpiApwNj3Kmp2uyz2uipU0UKhf/WqvmU96" + "yJj6j1JjZB6p+9sgecPFj1UMWhEFTwxMEwR7iZDvjkKDNWMit+0cQyeS7U0Lxn3u"
            + "m2g5e6C/1akwHZsioLC5OpFq/BkPtnbtuy4Kr5Kwb2y7vSiKpjFr7sKInjdAsgCi" + "8kyUV8MyaIfZdtREjwqBe0imfP+IPVqAsl1wGW95YXsLlK+4P1bspAgeHdDq7Q91"
            + "bJJQAS5OTD38i1NY6MRtt/fWsShVBLjf2FzNpw6siHHl2N7BDNyO3ALtgfp50e0Z" + "Dsw5WArgKLiXfwZIrIKbYA73RFc10ReDqnJSF+NXgBo1/i4WhZLHC1Osl5UoKt9q"
            + "UoXIUmYhAwdAT5ZKVw6A8yp4e270yZTXNsDz8u/onEwNc1iM0v0RnPQhNE5sKEZH" + "QrMxttiwbKe3YshCjbruz/27XnNA51t2p1M6eC1HRab4xSHAyH5NTxGJ8yKhOfiT"
            + "aBKqdTH3P7QzlcoCUDVDDe7aLMaZEf+a2Te63cZTuUVpkysxSjAjBgkqhkiG9w0B" + "CRQxFh4UAHAAcgBpAHYAYQB0AGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFCfeHSg6"
            + "EdeP5A1IC8ydjyrjyFSdAAQBAAQBAAQBAAQBAASCCBoAMIAGCSqGSIb3DQEHBqCA" + "MIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQURNy47tUcttscSleo"
            + "8gY6ZAPFOl0CAWSggASCB8jdZ+wffUP1B25Ys48OFBMg/itT0EBS6J+dYVofZ84c" + "x41q9U+CRMZJwVNZbkqfRZ+F3tLORSwuIcwyioa2/JUpv8uJCjQ2tru5+HtqCrzR"
            + "Huh7TfdiMqvjkKpnXi69DPPjQdCSPwYMy1ahZrP5KgEZg4S92xpU2unF1kKQ30Pq" + "PTEBueDlFC39rojp51Wsnqb1QzjPo53YvJQ8ztCoG0yk+0omELyPbc/qMKe5/g5h"
            + "Lx7Q+2D0PC/ZHtoDkCRfMDKwgwALFsSj2uWNJsCplspmc7YgIzSr/GqqeSXHp4Ue" + "dwVJAswrhpkXZTlp1rtl/lCSFl9akwjY1fI144zfpYKpLqfoHL1uI1c3OumrFzHd"
            + "ZldZYgsM/h3qjgu8qcXqI0sKVXsffcftCaVs+Bxmdu9vpY15rlx1e0an/O05nMKU" + "MBU2XpGkmWxuy0tOKs3QtGzHUJR5+RdEPURctRyZocEjJgTvaIMq1dy/FIaBhi+d"
            + "IeAbFmjBu7cv9C9v/jMuUjLroycmo7QW9jGgyTOQ68J+6w2/PtqiqIo3Ry9WC0SQ" + "8+fVNOGLr5O2YPpw17sDQa/+2gjozngvL0OHiABwQ3EbXAQLF046VYkTi5R+8iGV"
            + "3jlTvvStIKY06E/s/ih86bzwJWAQENCazXErN69JO+K3IUiwxac+1AOO5WyR9qyv" + "6m/yHdIdbOVE21M2RARbI8UiDpRihCzk4duPfj/x2bZyFqLclIMhbTd2UOQQvr+W"
            + "4etpMJRtyFGhdLmNgYAhYrbUgmdL1kRkzPzOs77PqleMpfkii7HPk3HlVkM7NIqd" + "dN0WQaQwGJuh5f1ynhyqtsaw6Gu/X56H7hpziAh0eSDQ5roRE7yy98h2Mcwb2wtY"
            + "PqVFTmoKuRWR2H5tT6gCaAM3xiSC7RLa5SF1hYQGaqunqBaNPYyUIg/r03dfwF9r" + "AkOhh6Mq7Z2ktzadWTxPl8OtIZFVeyqIOtSKBHhJyGDGiz3+SSnTnSX81NaTSJYZ"
            + "7YTiXkXvSYNpjpPckIKfjpBw0T4pOva3a6s1z5p94Dkl4kz/zOmgveGd3dal6wUV" + "n3TR+2cyv51WcnvB9RIp58SJOc+CvCvYTvkEdvE2QtRw3wt4ngGJ5pxmC+7+8fCf"
            + "hRDzw9LBNz/ry88y/0Bidpbhwr8gEkmHuaLp43WGQQsQ+cWYJ8AeLZMvKplbCWqy" + "iuks0MnKeaC5dcB+3BL55OvcTfGkMtz0oYBkcGBTbbR8BKJZgkIAx7Q+/rCaqv6H"
            + "HN/cH5p8iz5k+R3MkmR3gi6ktelQ2zx1pbPz3IqR67cTX3IyTX56F2aY54ueY17m" + "7hFwSy4aMen27EO06DXn/b6vPKj73ClE2B/IPHO/H2e8r04JWMltFWuStV0If5x0"
            + "5ZImXx068Xw34eqSWvoMzr97xDxUwdlFgrKrkMKNoTDhA4afrZ/lwHdUbNzh6cht" + "jHW/IfIaMo3NldN/ihO851D399FMsWZW7YA7//RrWzBDiLvh+RfwkMOfEpbujy0G"
            + "73rO/Feed2MoVXvmuKBRpTNyFuBVvFDwIzBT4m/RaVf5m1pvprSk3lo43aumdN9f" + "NDETktVZ/CYaKlYK8rLcNBKJicM5+maiQSTa06XZXDMY84Q0xtCqJ/aUH4sa/z8j"
            + "KukVUSyUZDJk/O82B3NA4+CoP3Xyc9LAUKucUvoOmGt2JCw6goB/vqeZEg9Tli0Q" + "+aRer720QdVRkPVXKSshL2FoXHWUMaBF8r//zT6HbjTNQEdxbRcBNvkUXUHzITfl"
            + "YjQcEn+FGrF8+HVdXCKzSXSgu7mSouYyJmZh42spUFCa4j60Ks1fhQb2H1p72nJD" + "n1mC5sZkU68ITVu1juVl/L2WJPmWfasb1Ihnm9caJ/mEE/i1iKp7qaY9DPTw5hw4"
            + "3QplYWFv47UA/sOmnWwupRuPk7ISdimuUnih8OYR75rJ0z6OYexvj/2svx9/O5Mw" + "654jFF2hAq69jt7GJo6VZaeCRCAxEU7N97l3EjqaKJVrpIPQ+3yLmqHit/CWxImB"
            + "iIl3sW7MDEHgPdQy3QiZmAYNLQ0Te0ygcIHwtPyzhFoFmjbQwib2vxDqWaMQpUM1" + "/W96R/vbCjA7tfKYchImwAPCyRM5Je2FHewErG413kZct5tJ1JqkcjPsP7Q8kmgw"
            + "Ec5QNq1/PZOzL1ZLr6ryfA4gLBXa6bJmf43TUkdFYTvIYbvH2jp4wpAtA152YgPI" + "FL19/Tv0B3Bmb1qaK+FKiiQmYfVOm/J86i/L3b8Z3jj8dRWEBztaI/KazZ/ZVcs/"
            + "50bF9jH7y5+2uZxByjkM/kM/Ov9zIHbYdxLw2KHnHsGKTCooSSWvPupQLBGgkd6P" + "M9mgE6MntS+lk9ucpP5j1LXo5zlZaLSwrvSzE3/bbWJKsJuomhRbKeZ+qSYOWvPl"
            + "/1RqREyZHbSDKzVk39oxH9EI9EWKlCbrz5EHWiSv0+9HPczxbO3q+YfqcY8plPYX" + "BvgxHUeDR+LxaAEcVEX6wd2Pky8pVwxQydU4cEgohrgZnKhxxLAvCp5sb9kgqCrh"
            + "luvBsHpmiUSCi/r0PNXDgApvTrVS/Yv0jTpX9u9IWMmNMrnskdcP7tpEdkw8/dpf" + "RFLLgqwmNEhCggfbyT0JIUxf2rldKwd6N1wZozaBg1uKjNmAhJc1RxsABAEABAEA"
            + "BAEABAEABAEABAEABAEABAEABAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUA" + "BBSS2GOUxqv3IT+aesPrMPNn9RQ//gQUYhjCLPh/h2ULjh+1L2s3f5JIZf0CAWQA"
            + "AA==").getBytes());

    private static final byte[] keys1024bit = Base64.decode(("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKA5rNhYbPuVcArT"
            + "mkthfrW2tX1Z7SkCD01sDYrkiwOcodFmS1cSyz8eHM51iwHA7CW0WFvfUjomBT5y" + "gRQfIsf5M5DUtYcKM1hmGKSPzvmF4nYv+3UBUesCvBXVRN/wFZ44SZZ3CVvpQUYb"
            + "GWjyC+Dgol5n8oKOC287rnZUPEW5AgMBAAECgYEAhMtoeyLGqLlRVFfOoL1cVGTr" + "BMp8ail/30435y7GHKc74p6iwLcd5uEhROhc3oYz8ogHV5W+w9zxKbGjU7b+jmh+"
            + "h/WFao+Gu3sSrZ7ieg95fSuQsBlJp3w+eCAOZwlEu/JQQHDtURui25SPVblZ9/41" + "u8VwFjk9YQx+nT6LclECQQDYlC9bOr1SWL8PBlipXB/UszMsTM5xEH920A+JPF4E"
            + "4tw+AHecanjr5bXSluRbWSWUjtl5LV2edqAP9EsH1/A1AkEAvWOctUvTlm6fWHJq" + "lZhsWVvOhDG7cn5gFu34J8JJd5QHov0469CpSamY0Q/mPE/y3kDllmyYvnQ+yobB"
            + "ZRg39QJBAINCM/0/eVQ58vlBKGTkL2pyfNYhapB9pjK04GWVD4o4j7CICfXjVYvq" + "eSq7RoTSX4NMnCLjyrRqQpHIxdxoE+0CQQCz7MzWWGF+Cz6LUrf7w0E8a8H5SR4i"
            + "GfnEDvSxIR2W4yWWLShEsIoEF4G9LHO5XOMJT3JOxIEgf2OgGQHmv2l5AkBThYUo" + "ni82jZuue3YqXXHY2lz3rVmooAv7LfQ63yzHECFsQz7kDwuRVWWRsoCOURtymAHp"
            + "La09g2BE+Q5oUUFx").getBytes());

    /** self signed cert done with above private key */
    private static final byte[] certbytes = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    private static final String storepwd = "foo123";
    private static final String pkAlias = "privateKey";

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testGetCertChain() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        ByteArrayInputStream fis = new ByteArrayInputStream(ks3);
        store.load(fis, storepwd.toCharArray());
        Certificate[] certs = KeyTools.getCertChain(store, pkAlias);
        log.debug("Number of certs: " + certs.length);
        assertEquals("Wrong number of certs returned", 3, certs.length);
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            log.debug("SubjectDN: " + cert.getSubjectDN().toString());
            if (i == 0) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=fooca,C=SE");
            }
            if (i == 1) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=TestSubCA,O=AnaTom,C=SE");
            }
            if (i == 2) {
                assertEquals("Wrong subjectDN", cert.getSubjectDN().toString(), "CN=TestCA,O=AnaTom,C=SE");
            }
        }
    }

    @Test
    public void testGenKeysRSA() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        // Test that fails
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        try {
        	KeyTools.testKey(pk, keys.getPublic(), "BC");
        	assertTrue(false);
        } catch (InvalidKeyException e) {
        	assertEquals("Not possible to sign and then verify with key pair.", e.getMessage());
        }
        
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertTrue((paramspec instanceof RSAKeyGenParameterSpec));
        RSAKeyGenParameterSpec rsaspec = (RSAKeyGenParameterSpec)paramspec;
        assertEquals(512, rsaspec.getKeysize());
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(out);
        KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        ps.close();
        String str = out.toString();
        assertTrue(str.contains("RSA key"));
    }

    @Test
    public void testCreateP12() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createP12("Foo", pk, cert, (X509Certificate) null);
        assertNotNull("ks must not be null", ks);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo123".toCharArray());
        assertTrue("baos size must not be 0", baos.size() > 0);
        Certificate cert1 = ks.getCertificate("Foo");
        assertNotNull(cert1);
        byte[] bytes = KeyTools.getSinglePemFromKeyStore(ks, "foo123".toCharArray());
        assertNotNull(bytes);
        String str = new String(bytes);
        assertTrue(str.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(str.contains("-----BEGIN CERTIFICATE-----"));
    }

    @Test
    public void testCreateJKS() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(certbytes);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createJKS("Foo", pk, "foo123", (X509Certificate)cert, null);
        assertNotNull("ks must not be null", ks);
        Certificate cert1 = ks.getCertificate("Foo");
        assertNotNull(cert1);
        byte[] bytes = KeyTools.getSinglePemFromKeyStore(ks, "foo123".toCharArray());
        assertNotNull(bytes);
        String str = new String(bytes);
        assertTrue(str.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(str.contains("-----BEGIN CERTIFICATE-----"));        
    }

    @Test
    public void testGenKeysECDSAx9() throws Exception {
        KeyPair keys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        // Verify that the keys are using maned curves, and not explicit parameters
        PrivateKeyInfo priv2 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        assertTrue("Private key is not encoded with named curves, but using explicit parameters", X962Parameters.getInstance(priv2.getPrivateKeyAlgorithm().getParameters()).isNamedCurve());
        SubjectPublicKeyInfo pub2 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        assertTrue("Public key is not encoded with named curves, but using explicit parameters", X962Parameters.getInstance(pub2.getAlgorithm().getParameters()).isNamedCurve());

        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, true);
        // log.debug(cert);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        // Test that fails
        KeyPair keys1 = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        try {
        	KeyTools.testKey(keys1.getPrivate(), keys.getPublic(), "BC");
        	assertTrue(false);
        } catch (InvalidKeyException e) {
        	assertEquals("Not possible to sign and then verify with key pair.", e.getMessage());
        }

        // This will not do anything for a key which is not an org.ejbca.cvc.PublicKeyEC
        PublicKey pk = KeyTools.getECPublicKeyWithParams(keys.getPublic(), "prime192v1");
        assertTrue(pk.equals(keys.getPublic()));
        pk = KeyTools.getECPublicKeyWithParams(keys.getPublic(), pk);
        assertTrue(pk.equals(keys.getPublic()));
        
        AlgorithmParameterSpec spec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertNotNull(spec);
        assertTrue((spec instanceof ECParameterSpec));
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(out);
        KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        ps.close();
        String str = out.toString();
        assertTrue(str.contains("Elliptic curve key"));
    }

    @Test
    public void testGenKeysECDSANist() throws Exception {
        KeyPair keys = KeyTools.genKeys("secp384r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, true);
        // log.debug(cert);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.info(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
    }

    @Test
    public void testGenKeysECDSAImplicitlyCA() throws Exception {
        KeyPair keys = KeyTools.genKeys("implicitlyCA", AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, true);
        // log.debug(cert);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.info(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
    }

    @Test
    public void testGenKeysECDSAFail() throws Exception {
    	try {
    		KeyTools.genKeys("fooBar", AlgorithmConstants.KEYALGORITHM_ECDSA);
    		assertTrue("This statement should throw", false);
    	} catch (InvalidAlgorithmParameterException e) {
    	}
    	try {
        	KeyTools.genKeys(null, null, AlgorithmConstants.KEYALGORITHM_ECDSA);
    		assertTrue("This statement should throw", false);
    	} catch (InvalidAlgorithmParameterException e) {
    	}
    }
    
    @Test
    public void testGenKeysDSA() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_DSA);
        assertNotNull("keys must not be null", keys);
        assertEquals("Length must be 512", 512, KeyTools.getKeyLength(keys.getPublic()));
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, true);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        // Test that fails
        KeyPair keys1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_DSA);
        try {
        	KeyTools.testKey(keys1.getPrivate(), keys.getPublic(), "BC");
        	assertTrue(false);
        } catch (InvalidKeyException e) {
        	assertEquals("Not possible to sign and then verify with key pair.", e.getMessage());
        }
        
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertTrue((paramspec instanceof DSAParameterSpec));
        DSAParameterSpec dsaspec = (DSAParameterSpec)paramspec;
        assertEquals(512, dsaspec.getP().bitLength());
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(out);
        KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        ps.close();
        String str = out.toString();
        assertTrue(str.contains("DSA key"));
    }

    @Test
    public void testGenKeysECDSAAlgorithmSpec() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("EC", "BC");
        AlgorithmParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals("EC", keys.getPublic().getAlgorithm());
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals("secp256r1", spec);
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());

        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_ECDSA);
        assertEquals("ECDSA", keys2.getPublic().getAlgorithm());
        ECPublicKey pk1 = (ECPublicKey) keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey) keys2.getPublic();
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        assertEquals(len1, len2);
        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
    }

    @Test
    public void testGetECDSACvcPubKeyParams() throws Exception {
    	// Test to enrich an EC public key that does not contain domain parameters 
    	// with domain parameters from either another EC public key or from the curve name
    	
		// A CVCA certificate will contain the complete ECC params 
		CVCertificate cert1 = createCVTestCertificate(AuthorizationRoleEnum.CVCA);
		CVCPublicKey pk1 = cert1.getCertificateBody().getPublicKey();

		// An IS certificate will not contain the complete ECC params 
		CVCertificate cert2 = createCVTestCertificate(AuthorizationRoleEnum.IS);
		CVCPublicKey pk2 = cert2.getCertificateBody().getPublicKey();

		ECPublicKey ecpk1 = (ECPublicKey)pk1;
		ECPublicKey ecpk2 = (ECPublicKey)pk2;
		ECParameterSpec spec1 = ecpk1.getParams();
		assertNotNull(spec1);
		ECParameterSpec spec2 = ecpk2.getParams();
		assertNull(spec2); // no parameters in IS cert
		ECPublicKey ecpk3 = (ECPublicKey)KeyTools.getECPublicKeyWithParams(pk2, pk1);
		ECParameterSpec spec3 = ecpk3.getParams();
		assertNotNull(spec3);
		
		spec2 = ecpk2.getParams();
		assertNull(spec2); // no parameters in IS cert
		ECPublicKey ecpk4 = (ECPublicKey)KeyTools.getECPublicKeyWithParams(ecpk2, "prime192v1");
		ECParameterSpec spec4 = ecpk4.getParams();
		assertNotNull(spec4);

		// Trying to enrich with another public key with no params will give no params in enriched key
		ECPublicKey ecpk5 = (ECPublicKey)KeyTools.getECPublicKeyWithParams(ecpk2, ecpk2);
		ECParameterSpec spec5 = ecpk5.getParams();
		assertNull(spec5);

    }
    
	// Helper method to create a test CV certificate
	private CVCertificate createCVTestCertificate(AuthorizationRoleEnum role) throws Exception {
		KeyPair keyPair = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
		CAReferenceField caRef = new CAReferenceField("SE", "TEST001", "00001");
		HolderReferenceField holderRef = new HolderReferenceField("SE", "TEST002", "SE001");
		// Call method in CertificateGenerator
		return CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", role);
	}
	
	@Test
	public void testGenKeysGOSTAlgorithmSpec() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        log.trace(">testGenKeysGOSTAlgorithmSpec");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECGOST3410", "BC");
        
        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec); 
        keygen.initialize(ecSpec);
        
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys.getPublic().getAlgorithm());
        
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals(keyspec, spec);
        
        ECPublicKey ecpub = (ECPublicKey) keys.getPublic();
        java.security.spec.ECParameterSpec sunsp = ecpub.getParams();
        sunsp.getCurve(); // return value not tested
        
        // Nothing to do here, the gost parameter seem to behave similarly to EC parameter
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        
        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        KeyPair keys3 = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys2.getPublic().getAlgorithm());
        assertEquals(AlgorithmConstants.KEYALGORITHM_ECGOST3410, keys3.getPublic().getAlgorithm());
        
        ECPublicKey pk1 = (ECPublicKey)keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey)keys2.getPublic();
        ECPublicKey pk3 = (ECPublicKey)keys3.getPublic();
        
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        int len3 = KeyTools.getKeyLength(pk3);
        
        assertEquals(len1, len2);
        assertEquals(len1, len3);

        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        ECParameterSpec ecs3 = pk3.getParams();
        
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        
        assertEquals(ecs1.getCofactor(), ecs3.getCofactor());
        assertEquals(ecs1.getOrder(), ecs3.getOrder());
        assertEquals(ecs1.getCurve(), ecs3.getCurve());
        
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        assertFalse(pk1.getW().equals(pk3.getW()));
        
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        
        byte[] signature = KeyTools.signData(keys2.getPrivate(),
                AlgorithmConstants.KEYALGORITHM_ECGOST3410,
                "Hello world ! How cool is ejbca ??".getBytes());
        
        assertTrue(KeyTools.verifyData(keys2.getPublic(),
                AlgorithmConstants.KEYALGORITHM_ECGOST3410,
                "Hello world ! How cool is ejbca ??".getBytes(),
                signature));
        
        
        ECPublicKeySpec ecspec = new ECPublicKeySpec(pk2.getW(), pk2.getParams());
        KeyFactory.getInstance("ECGOST3410").generatePublic(ecspec); // return value not tested
        KeyFactory.getInstance("EC").generatePublic(ecspec); // return value not tested
        
        log.trace("<testGenKeysGOSTAlgorithmSpec");
    }
	
	@Test
    public void testGenKeysDSTU4145AlgorithmSpec() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        log.trace(">testGenKeysDSTU4145AlgorithmSpec");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec); 
        keygen.initialize(ecSpec);
        
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys.getPublic().getAlgorithm());
        
        String spec = AlgorithmTools.getKeySpecification(keys.getPublic());
        assertEquals(keyspec, spec);
        
        ECPublicKey ecpub = (ECPublicKey) keys.getPublic();
        java.security.spec.ECParameterSpec sunsp = ecpub.getParams();
        sunsp.getCurve(); // return value not tested
        
        // Nothing to do here, the gost parameter seem to behave similarly to EC parameter
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(keys.getPublic());
        
        KeyPair keys2 = KeyTools.genKeys(null, paramspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
        KeyPair keys3 = KeyTools.genKeys(keyspec, AlgorithmConstants.KEYALGORITHM_DSTU4145);
        
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys2.getPublic().getAlgorithm());
        assertEquals(AlgorithmConstants.KEYALGORITHM_DSTU4145, keys3.getPublic().getAlgorithm());
        
        ECPublicKey pk1 = (ECPublicKey)keys.getPublic();
        ECPublicKey pk2 = (ECPublicKey)keys2.getPublic();
        ECPublicKey pk3 = (ECPublicKey)keys3.getPublic();
        
        // Verify that it's the same key size
        int len1 = KeyTools.getKeyLength(pk1);
        int len2 = KeyTools.getKeyLength(pk2);
        int len3 = KeyTools.getKeyLength(pk3);
        
        assertEquals(len1, len2);
        assertEquals(len1, len3);

        // Verify that the domain parameters are the same
        ECParameterSpec ecs1 = pk1.getParams();
        ECParameterSpec ecs2 = pk2.getParams();
        ECParameterSpec ecs3 = pk3.getParams();
        
        assertEquals(ecs1.getCofactor(), ecs2.getCofactor());
        assertEquals(ecs1.getOrder(), ecs2.getOrder());
        assertEquals(ecs1.getCurve(), ecs2.getCurve());
        
        assertEquals(ecs1.getCofactor(), ecs3.getCofactor());
        assertEquals(ecs1.getOrder(), ecs3.getOrder());
        assertEquals(ecs1.getCurve(), ecs3.getCurve());
        
        // Verify that it is not the same key though
        assertFalse(pk1.getW().equals(pk2.getW()));
        assertFalse(pk1.getW().equals(pk3.getW()));
        
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), "BC");
        
        byte[] signature = KeyTools.signData(keys2.getPrivate(),
                AlgorithmConstants.KEYALGORITHM_DSTU4145,
                "Hello world ! How cool is ejbca ??".getBytes());
        
        assertTrue(KeyTools.verifyData(keys2.getPublic(),
                AlgorithmConstants.KEYALGORITHM_DSTU4145,
                "Hello world ! How cool is ejbca ??".getBytes(),
                signature));
        
        
        ECPublicKeySpec ecspec = new ECPublicKeySpec(pk2.getW(), pk2.getParams());
        KeyFactory.getInstance("DSTU4145").generatePublic(ecspec); // return value not tested
        KeyFactory.getInstance("EC").generatePublic(ecspec); // return value not tested
        
        log.trace("<testGenKeysDSTU4145AlgorithmSpec");
    }

	
}
