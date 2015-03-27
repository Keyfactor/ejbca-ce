/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
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
import static org.junit.Assume.assumeTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockDSAPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockDSTU4145PublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockECDSAPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockGOST3410PublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockNotSupportedPublicKey;
import org.cesecore.certificates.util.AlgorithmToolsHelper.MockRSAPublicKey;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
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
        final String ecNamedCurve = AlgorithmTools.getKeySpecification(pair.getPublic());
        assertTrue("Key was generated with the right curve.", AlgorithmTools.getEcKeySpecAliases(ecNamedCurve).contains("prime192v1"));
        assertTrue("Key was generated with the right curve.", AlgorithmTools.getEcKeySpecAliases(ecNamedCurve).contains("secp192r1"));
        // We can't really say if "secp192r1" or "prime192v1" should be the preferred name on this system, since it depends on available providers.
        //assertEquals("Unexpected preferred named curve alias.", "secp192r1", ecNamedCurve);
        pair = KeyTools.genKeys("1024", "DSA");
        assertEquals("1024", AlgorithmTools.getKeySpecification(pair.getPublic()));
    }
    
    @Test
    public void testGetKeySpecificationGOST3410() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("ECGOST3410", "BC");
        AlgorithmParameterSpec ecSpec = ECGOST3410NamedCurveTable.getParameterSpec(keyspec); 
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(keyspec, AlgorithmTools.getKeySpecification(keys.getPublic()));
    }
    
    @Test
    public void testGetKeySpecificationDSTU4145() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        final String keyspec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        AlgorithmParameterSpec ecSpec = KeyTools.dstuOidToAlgoParams(keyspec); 
        keygen.initialize(ecSpec);
        KeyPair keys = keygen.generateKeyPair();
        assertEquals(keyspec, AlgorithmTools.getKeySpecification(keys.getPublic()));
    }

    @Test
    public void testGetEncSigAlgFromSigAlg() {
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
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
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmTools.getEncSigAlgFromSigAlg(AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145));
        assertEquals("Foobar", AlgorithmTools.getEncSigAlgFromSigAlg("Foobar"));
    }

    @Test
    public void testIsCompatibleSigAlg() {
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockRSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockECDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));

    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA224_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA));
    	assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSAPublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA));
    }
    
    @Test
    public void testIsCompatibleSigAlgGOST3410() {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
    	assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockGOST3410PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145));
    }
    
    @Test
    public void testIsCompatibleSigAlgDSTU4145() {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        assertTrue(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_DSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA384_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_SHA512_WITH_RSA));
        assertFalse(AlgorithmTools.isCompatibleSigAlg(new MockDSTU4145PublicKey(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410));
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
    	assertEquals("SHA1WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1rsa));
    	assertEquals("MD5WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(md5rsa));
    	assertEquals("SHA256WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256rsa));
    	assertEquals("SHA384WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha384rsa));
    	assertEquals("SHA512WITHRSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha512rsa));
    	assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1rsamgf));
    	assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256rsamgf));
    	
    	assertEquals("SHA1WithRSA", AlgorithmTools.getSignatureAlgorithm(sha1rsa));
    	assertEquals("MD5WithRSA", AlgorithmTools.getSignatureAlgorithm(md5rsa));
    	assertEquals("SHA256WithRSA", AlgorithmTools.getSignatureAlgorithm(sha256rsa));
    	assertEquals("SHA384WithRSA", AlgorithmTools.getSignatureAlgorithm(sha384rsa));
    	assertEquals("SHA512WithRSA", AlgorithmTools.getSignatureAlgorithm(sha512rsa));
    	assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha1rsamgf));
    	assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(sha256rsamgf));
    	
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
    	assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(cvsha1mgf));
    	assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(cvsha256mgf));

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
        Certificate sha512ecc = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), "SHA512WithECDSA", true);
    	assertEquals("ECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha1ecc));
    	assertEquals("SHA224WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha224ecc));
    	assertEquals("SHA256WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha256ecc));
    	assertEquals("SHA384WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha384ecc));
        assertEquals("SHA512WITHECDSA", AlgorithmTools.getCertSignatureAlgorithmNameAsString(sha512ecc));

    	assertEquals("SHA1withECDSA", AlgorithmTools.getSignatureAlgorithm(sha1ecc));
    	assertEquals("SHA224withECDSA", AlgorithmTools.getSignatureAlgorithm(sha224ecc));
    	assertEquals("SHA256withECDSA", AlgorithmTools.getSignatureAlgorithm(sha256ecc));
    	assertEquals("SHA384withECDSA", AlgorithmTools.getSignatureAlgorithm(sha384ecc));
        assertEquals("SHA512withECDSA", AlgorithmTools.getSignatureAlgorithm(sha512ecc));

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
    
    @Test
    public void testCertSignatureAlgorithmAsStringGOST3410() throws Exception {
        assumeTrue(AlgorithmTools.isGost3410Enabled());
        KeyPair keyPair = KeyTools.genKeys(CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B"), AlgorithmConstants.KEYALGORITHM_ECGOST3410);
        Certificate gost3411withgost3410 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410, true);
        assertEquals("GOST3411WITHECGOST3410", AlgorithmTools.getCertSignatureAlgorithmNameAsString(gost3411withgost3410));
        assertEquals("GOST3411withECGOST3410", AlgorithmTools.getSignatureAlgorithm(gost3411withgost3410));
    }
    
    @Test
    public void testCertSignatureAlgorithmAsStringDSTU4145() throws Exception {
        assumeTrue(AlgorithmTools.isDstu4145Enabled());
        KeyPair keyPair = KeyTools.genKeys(CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233"), AlgorithmConstants.KEYALGORITHM_DSTU4145);
        Certificate gost3411withgost3410 = CertTools.genSelfCert("CN=TEST", 10L, null, keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145, true);
        assertEquals("GOST3411WITHDSTU4145", AlgorithmTools.getCertSignatureAlgorithmNameAsString(gost3411withgost3410));
        assertEquals("GOST3411withDSTU4145", AlgorithmTools.getSignatureAlgorithm(gost3411withgost3410));
    }

}
