/*************************************************************************
 *                                                                       *
a *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.cesecore.certificates.certificate.cvc.CvCertificateUtility;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.keys.KeyTools;

/**
 *
 */
public class CertToolsCvcUnitTest {

    private static byte[] cvccert = Base64.decode(("fyGCAWF/ToHZXykBAEIKU0VSUFMxMDExMH9JgZUGCgQAfwAHAgICAQGBgYEAk4Aq"
            + "LqYXchIouF9yBv/2hFnf5N65hdpvQPUdfH1k2qnHAlOL5DYYlKCBh8YFCC2RZD+K" + "nJ99cHxh8oxh28U23Z/MqTOKv5tR8JIUUm3G3Hjj2erVVTEJ49MqLzsyVGfw4yCu"
            + "YRdwBYFWJu2t6PcS5KPnpNtbNdBzrDJAqxPAsO2CAwEAAV8gClNFUlBTMTAxMTB/" + "TA4GCQQAfwAHAwECAVMBw18lBgAIAAUABV8kBgEAAAUABV83gYB88jfXZ3njYpuD"
            + "4fpS6BV53y9+iz3KAQM/74LPMI49elGtcAVyMn1EMn/bU4MeMARfv3Njd2Go4ZhM" + "j5xuY2Pvktz3Dq4ogjkgqAJqqIvG+M9KXh9XAv2m2wjmsueKbXUJ8TpJR87k4o97"
            + "buZXbuStDOb5FibhxyVgWIxuCn8quQ==").getBytes());

    private static byte[] cvcreqrenew = Base64.decode(("Z4IBtn8hggFmf06CASZfKQEAQg5TRUlTQlBPT0wwMDAwNn9Jgf0GCgQAfwAHAgIC"
            + "AgKBHNfBNKomQ2aGKhgwJXXR14ewnwdXl9qJ9X7IwP+CHGil5iypzmwcKZgDpsFT" + "C1FOGCrYsAQqWcrSn0ODHCWA9jzP5EE4hwcTsakjaeM+ITXSZtuzcjhsQAuEOQQN"
            + "kCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW93LAcm8kxrieTs2sJDVLnpnK" + "o/bTdhQCzYUc18E0qiZDZoYqGDAlddD7mNEWvEtt3ryjpaeTn4Y5BBQte2aU3YOQ"
            + "Ykf73/UluNQOpMlnHt9PXplomqhuAZ0QxwXb6TCG3rZJhVwe0wx0R1mqz3U+fJnU" + "hwEBXyAOU0VJU0JQT09MMDAwMDZfNzgErOAjPCoQ+WN8K6pzztZp+Mt6YGNkJzkk"
            + "WdLnvfPGZkEF0oUjcw+NjexaNCLOA0mCfu4oQwsjrUIOU0VJU0JQT09MMDAwMDVf" + "NzhSmH1c7YJhbLTRzwuSozUd9hlBHKEIfFqSUE9/FrbWXEtR+rHRYKAGu/nw8PAH"
            + "oM+HPMzMVVLDVg==").getBytes());

    private static byte[] cvcreq = Base64.decode(("fyGCAWZ/ToIBJl8pAQBCDlNFSVNCUE9PTDAwMDA1f0mB/QYKBAB/AAcCAgICAoEc"
            + "18E0qiZDZoYqGDAlddHXh7CfB1eX2on1fsjA/4IcaKXmLKnObBwpmAOmwVMLUU4Y" + "KtiwBCpZytKfQ4McJYD2PM/kQTiHBxOxqSNp4z4hNdJm27NyOGxAC4Q5BA2QKa0s"
            + "flz0NAgjsqh9xoyeTOMXTB5u/e4SwH1Yqlb3csBybyTGuJ5OzawkNUuemcqj9tN2" + "FALNhRzXwTSqJkNmhioYMCV10PuY0Ra8S23evKOlp5OfhjkEOwPDLflRVBj2iayW"
            + "VzpO2BICGO+PqFeuce1EZM4o1EIfLzoackPowabEMANfNltZvt5bWyzkZleHAQFf" + "IA5TRUlTQlBPT0wwMDAwNV83OEnwL+XYDhXqK/0fBuZ6lZV0HncoZyn3oo8MmaUL"
            + "2mNzpezLAoZMux0l5aYperrSDsuHw0zrf0yo").getBytes());
    
    private static byte[] cvccertchainroot = Base64.decode(("fyGCAmx/ToIBYl8pAQBCDlNFSFNNQ1ZDQTAwMDAxf0mCARUGCgQAfwAHAgICAQKB"
            + "ggEAyGju6NHTACB+pl2x27/VJVKuGBTgf98j3gQOyW5vDzXI7PkiwR1/ObPjFiuW" + "iBRH0WsPzHX7A3jysZr7IohLjy4oQMdP5z282/ZT4mBwlVu5pAEcHt2eHbpILwIJ"
            + "Hbv6130T+RoG/3bI/eHk9HWi3/ipVnwRX1CsylczFfdyPTMyGOJmmElT0GQgV8Rt" + "b5Us/Hz66qiUX67eRBrahJfwiVwawYzmZ5Rn9u/vXHQYeUh+lLja+H+kXof9ARuw"
            + "p5S09DO2VZWbbR2BZHk0IaNgo54Xoih+5c/nIA/2+j9Afdf+wuqmxqib5aPOMHO3" + "WOVmVMF84Xo2V+duIZ4b7KkRXYIDAQABXyAOU0VIU01DVkNBMDAwMDF/TA4GCQQA"
            + "fwAHAwECAVMBw18lBgAIAAUCBl8kBgEAAAUCBl83ggEAMiiqI+HF8DyhPfH8dTeU" + "4/0/DNnjZ2/Qy1a5GATWU04da+L2iWI8QclN64cw0l/zroBGyeq+flDKzVWnqril"
            + "HX/PD3/xoCEhZSfZ/1AQZBP39/t1lYZLJ36VeFwrsmvN8rq6RnNtR2CrDYDFkFRq" + "A6v9dNYMbnEDN7m8wD/DWM2fZr+loqznT1/egx+SBqUY+KnU6ntxQyw7gzL1DV9Z"
            + "OlyxjDaWY8i2Q/tcdDxdZYBBMgFhxivXV5ou2YiBZKKIlP2ots6P8TlSVwdyaHTI" + "8z8Hpvx1QcB2maOVn6IFAyq/X71p9Zb626YLhjaFO6v80SYnlefVu5Uir5n/HzpW"
            + "kg==").getBytes());

    private static byte[] cvccertchainsub = Base64.decode(("fyGCAeV/ToHcXykBAEIOU0VIU01DVkNBMDAwMDF/SYGUBgoEAH8ABwICAgECgYGA"
            + "rdRouw7ksS6M5kw28YkWAD350vbDlnPCmqsKPfKiNvDxowviWDUTn9Ai3xpTIzGO" + "cl40DqxYPA2X4XO52+r5ZUazsVyyx6F6XwznHdjUpDff4QFyG74Vjq7DDrCCKOzH"
            + "b0H6rNJFC5YEKI4wpEPou+3bq2jhLWkzU35EfydJHXWCAwEAAV8gClNFUlBTRFZF" + "WDJ/TA4GCQQAfwAHAwECAVMBgl8lBgAIAAYABV8kBgEAAAUCBl83ggEAbawFepay"
            + "gX+VrBOsGzbQCpG2mR1NrJbaNdBJcouWYTNzlDP/hRssU9/lTzHulRPupkarepAI" + "GMIDMOo3lNImlYlU8ZlaV6mbKRgWZVjtZmVgq+wLARS4dXNlHRJvS2AustfseGVr"
            + "kqJ0+UYo8x8UL13fB7VCSVqADnOnbemtvE1cIdFcIAqP1JLh91ACJ4lpoaAn10+g" + "5coIGGa01BYEDtiA++SFnRl7kYFykAZrs3eXq+zuPmOo9hr4JxLZuiN5DnIrZdLA"
            + "DWq7GeCFr6wCMg2jPuK9Kqvl06tqylVy4ravVHv58WvAxWFgyuezdRbyV7YAfVF3" + "tlcVDXa3R+mfYg==").getBytes());
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new CvCertificateUtility());
        Security.addProvider(new CVCProvider());     
    }
    
    @Test
    public void testCvcCert() throws Exception {
        Certificate cert = CertTools.getCertfromByteArray(cvccert, Certificate.class);
        assertNotNull(cert);
        PublicKey pk = cert.getPublicKey();
        assertNotNull(pk);
        assertEquals("RSA", pk.getAlgorithm());
        if (pk instanceof RSAPublicKey) {
            BigInteger modulus = ((RSAPublicKey) pk).getModulus();
            int len = modulus.bitLength();
            assertEquals(1024, len);
        } else {
            fail();
        }
        String subjectdn = CertTools.getSubjectDN(cert);
        assertEquals("CN=RPS,C=SE", subjectdn);
        String issuerdn = CertTools.getIssuerDN(cert);
        assertEquals("CN=RPS,C=SE", issuerdn);
        assertEquals("10110", CertTools.getSerialNumberAsString(cert));
        assertEquals("10110", CertTools.getSerialNumber(cert).toString());
        // Get signature field
        byte[] sign = CertTools.getSignature(cert);
        assertEquals(128, sign.length);
        // Check validity dates
        final long MAY5_0000_2008_GMT = 1209945600000L; 
        final long MAY5_0000_2008_GMT_MINUS1MS = 1209945599999L; 
        final long MAY5_2359_2010_GMT = 1273103999000L; 
        final long MAY5_2359_2010_GMT_PLUS1MS = 1273103999001L;
        
        assertEquals(MAY5_0000_2008_GMT, CertTools.getNotBefore(cert).getTime());
        assertEquals(MAY5_2359_2010_GMT, CertTools.getNotAfter(cert).getTime());
        assertTrue(CertTools.isCA(cert));
        CardVerifiableCertificate cvcert = (CardVerifiableCertificate) cert;
        assertEquals("CVCA", cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole().name());
        CertTools.checkValidity(cert, new Date(MAY5_0000_2008_GMT));
        CertTools.checkValidity(cert, new Date(MAY5_2359_2010_GMT));
        try {
            CertTools.checkValidity(cert, new Date(MAY5_0000_2008_GMT_MINUS1MS));
            fail("Should throw");
        } catch (CertificateNotYetValidException e) {
            // NOPMD
        }
        try {
            CertTools.checkValidity(cert, new Date(MAY5_2359_2010_GMT_PLUS1MS));
            fail("Should throw");
        } catch (CertificateExpiredException e) {
            // NOPMD
        }       

        // Serialization, CVC provider is installed by CryptoProviderTools.installBCProvider
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(cert);
        oos.close();
        baos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object o = ois.readObject();
        Certificate ocert = (Certificate) o;
        assertEquals("CVC", ocert.getType());

        // Test CVC certificate request encoding
        CVCObject parsedObject = CertificateParser.parseCVCObject(cvcreq);
        CVCertificate req = (CVCertificate) parsedObject;
        PublicKey pubKey = req.getCertificateBody().getPublicKey();
        assertNotNull(pubKey);
        assertEquals("CVC", pubKey.getFormat());
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();
        int len = modulus.bitLength();
        assertEquals(1024, len);

        // Test verification of an authenticated request
        parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
        CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest) parsedObject;
        try {
            authreq.verify(pubKey);
        } catch (Exception e) {
            fail("Exception verifying authenticated request: " + e.getMessage());
        }
        // Test verification of an authenticated request that fails
        parsedObject = CertificateParser.parseCVCObject(cvcreqrenew);
        authreq = (CVCAuthenticatedRequest) parsedObject;
        req = authreq.getRequest();
        try {
            authreq.verify(req.getCertificateBody().getPublicKey());
            fail("verifying authenticated request should have failed");
        } catch (Exception e) { // NOPMD:
        }
        
        // IS cert
        KeyPair keyPair = KeyTools.genKeys("prime192v1", "ECDSA");
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "HOLDERRE", "00000");
        CVCertificate cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha1 = new CardVerifiableCertificate(cv);
        assertFalse(CertTools.isCA(cvsha1));
    }
    
    @Test
    public void testCreateCertChain() throws Exception {
        // Test creating a certificate chain for CVC CAs
        Certificate cvccertroot = CertTools.getCertfromByteArray(cvccertchainroot, Certificate.class);
        Certificate cvccertsub = CertTools.getCertfromByteArray(cvccertchainsub, Certificate.class);
        assertTrue(CertTools.isCA(cvccertsub)); // DV is a CA also
        assertTrue(CertTools.isCA(cvccertroot));

        ArrayList<Certificate> certlist = new ArrayList<>();
        certlist.add(cvccertsub);
        certlist.add(cvccertroot);
        Collection<Certificate> col = CertTools.createCertChain(certlist);
        assertEquals(2, col.size());
        Iterator<Certificate> iter = col.iterator();
        Certificate certsub = iter.next();
        assertEquals("CN=RPS,C=SE", CertTools.getSubjectDN(certsub));
        Certificate certroot = iter.next();
        assertEquals("CN=HSMCVCA,C=SE", CertTools.getSubjectDN(certroot));
    }


}
