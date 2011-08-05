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

package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.cesecore.certificates.util.AlgorithmToolsHelper.MockDSAPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockECDSAPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockNotSupportedPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockRSAPublicKey;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for AlgorithmTools. Mostly tests border cases.
 * 
 * Based on EJBCA version: AlgorithmToolsTest.java 10833 2010-12-13 14:00:06Z anatom
 * 
 * @version $Id$
 */
public class AlgorithmToolsTest {

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testGetKeyAlgorithm() {
        assertNull("null if no match", AlgorithmTools.getKeyAlgorithm(new MockNotSupportedPublicKey()));
    }

    @Test
    public void testGetSignatureAlgorithms() {
        Collection<String> algs = AlgorithmTools.getSignatureAlgorithms(new MockNotSupportedPublicKey());
        assertNotNull("should not return null", algs);
        assertTrue("no supported algs", algs.isEmpty());
    }

    @Test
    public void testGetKeyAlgorithmFromSigAlg() {

        Collection<String> sigAlgs;

        // Test that key algorithm is RSA for all of its signature algorithms
        sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockRSAPublicKey());
        for (Iterator<String> i = sigAlgs.iterator(); i.hasNext();) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockRSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(i.next()));
        }

        // Test that key algorithm is DSA for all of its signature algorithms
        sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockDSAPublicKey());
        for (Iterator<String> i = sigAlgs.iterator(); i.hasNext();) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(i.next()));
        }

        // Test that key algorithm is ECDSA for all of its signature algorithms
        sigAlgs = AlgorithmTools.getSignatureAlgorithms(new MockECDSAPublicKey());
        for (Iterator<String> i = sigAlgs.iterator(); i.hasNext();) {
            assertEquals(AlgorithmTools.getKeyAlgorithm(new MockECDSAPublicKey()), AlgorithmTools.getKeyAlgorithmFromSigAlg(i.next()));
        }

        // should return a default value
        assertNotNull("should return a default value", AlgorithmTools.getKeyAlgorithmFromSigAlg("_NonExistingAlg"));

    }

    @Test
    public void testGetKeySpecification() throws Exception {
        assertNull("null if the key algorithm is not supported", AlgorithmTools.getKeySpecification(new MockNotSupportedPublicKey()));
        assertEquals("unknown", AlgorithmTools.getKeySpecification(new MockECDSAPublicKey()));
        assertEquals("10", AlgorithmTools.getKeySpecification(new MockRSAPublicKey()));
        KeyPair pair = KeyTools.genKeys("prime192v1", "ECDSA");
        assertEquals("prime192v1", AlgorithmTools.getKeySpecification(pair.getPublic()));
        pair = KeyTools.genKeys("1024", "DSA");
        assertEquals("1024", AlgorithmTools.getKeySpecification(pair.getPublic()));
    }

    @Test
    public void testGetEncSigAlgFromSigAlg() {
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA384_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA512_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1));
        assertEquals(AlgorithmConstants.SIGALG_MD5_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_MD5_WITH_RSA));
    }

    @Test
    public void testIsCompatibleSigAlg() {
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_MD5_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_MD5_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_MD5_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    }
    
    @Test
    public void testCertSignatureAlgorithmAsString() throws Exception {
    	// Generate a few certs with different algorithms
    	KeyPair keyPair = KeyTools.genKeys("1024", "RSA");
    	Certificate sha1rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithRSA", true);
    	Certificate md5rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "MD5WithRSA", true);
    	Certificate sha256rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithRSA", true);
    	Certificate sha384rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA384WithRSA", true);
    	Certificate sha512rsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA512WithRSA", true);
    	Certificate sha1rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithRSAAndMGF1", true);
    	Certificate sha256rsamgf = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithRSAAndMGF1", true);
    	assertEquals("SHA1WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1rsa));
    	assertEquals("MD5WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(md5rsa));
    	assertEquals("SHA256WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256rsa));
    	assertEquals("SHA384WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha384rsa));
    	assertEquals("SHA512WithRSAEncryption", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha512rsa));
    	assertEquals("SHA1WithRSAAndMGF1", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1rsamgf));
    	assertEquals("SHA256WithRSAAndMGF1", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256rsamgf));
    	
    	assertEquals("SHA1WithRSA", AlgorithmTools.getSignatureAlgorithm(sha1rsa));
    	assertEquals("MD5WithRSA", AlgorithmTools.getSignatureAlgorithm(md5rsa));
    	assertEquals("SHA256WithRSA", AlgorithmTools.getSignatureAlgorithm(sha256rsa));
    	assertEquals("SHA384WithRSA", AlgorithmTools.getSignatureAlgorithm(sha384rsa));
    	assertEquals("SHA512WithRSA", AlgorithmTools.getSignatureAlgorithm(sha512rsa));
    	assertEquals("SHA1WithRSAAndMGF1", AlgorithmTools.getSignatureAlgorithm(sha1rsamgf));
    	assertEquals("SHA256WithRSAAndMGF1", AlgorithmTools.getSignatureAlgorithm(sha256rsamgf));
    	
    	// CVC
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "HOLDERRE", "00000");
        CVCertificate cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha1 = new CardVerifiableCertificate(cv);
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha256 = new CardVerifiableCertificate(cv);
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSAAndMGF1", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha1mgf = new CardVerifiableCertificate(cv);
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithRSAAndMGF1", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha256mgf = new CardVerifiableCertificate(cv);
    	assertEquals("SHA1WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha1));
    	assertEquals("SHA256WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha256));
    	assertEquals("SHA1WITHRSAANDMGF1", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha1mgf));
    	assertEquals("SHA256WITHRSAANDMGF1", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha256mgf));
    	
    	assertEquals("SHA1WithRSA", AlgorithmTools.getSignatureAlgorithm(cvsha1));
    	assertEquals("SHA256WithRSA", AlgorithmTools.getSignatureAlgorithm(cvsha256));
    	assertEquals("SHA1WithRSAAndMGF1", AlgorithmTools.getSignatureAlgorithm(cvsha1mgf));
    	assertEquals("SHA256WithRSAAndMGF1", AlgorithmTools.getSignatureAlgorithm(cvsha256mgf));

    	// DSA
    	keyPair = KeyTools.genKeys("1024", "DSA");
    	Certificate sha1rsadsa = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithDSA", true);
    	assertEquals("DSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1rsadsa));
    	assertEquals("SHA1WithDSA", AlgorithmTools.getSignatureAlgorithm(sha1rsadsa));

        // ECC
    	keyPair = KeyTools.genKeys("prime192v1", "ECDSA");
    	Certificate sha1ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA1WithECDSA", true);
    	Certificate sha224ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA224WithECDSA", true);
    	Certificate sha256ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA256WithECDSA", true);
    	Certificate sha384ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA384WithECDSA", true);
    	assertEquals("ECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1ecc));
    	assertEquals("SHA224WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha224ecc));
    	assertEquals("SHA256WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256ecc));
    	assertEquals("SHA384WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha384ecc));

    	assertEquals("SHA1withECDSA", AlgorithmTools.getSignatureAlgorithm(sha1ecc));
    	assertEquals("SHA224withECDSA", AlgorithmTools.getSignatureAlgorithm(sha224ecc));
    	assertEquals("SHA256withECDSA", AlgorithmTools.getSignatureAlgorithm(sha256ecc));
    	assertEquals("SHA384withECDSA", AlgorithmTools.getSignatureAlgorithm(sha384ecc));

    	// CVC
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha1ecc = new CardVerifiableCertificate(cv);
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA224WithECDSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha224ecc = new CardVerifiableCertificate(cv);
        cv = CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithECDSA", AuthorizationRoleEnum.IS);
        CardVerifiableCertificate cvsha256ecc = new CardVerifiableCertificate(cv);
    	assertEquals("SHA1WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha1ecc));
    	assertEquals("SHA224WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha224ecc));
    	assertEquals("SHA256WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(cvsha256ecc));

    	assertEquals("SHA1withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha1ecc));
    	assertEquals("SHA224withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha224ecc));
    	assertEquals("SHA256withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha256ecc));

    }

}
