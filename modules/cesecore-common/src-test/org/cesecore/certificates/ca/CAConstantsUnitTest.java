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

package org.cesecore.certificates.ca;

import java.security.PublicKey;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CAConstantsUnitTest {
    private static final Logger log = Logger.getLogger(CAConstantsUnitTest.class);

    @Before
    public void installBcProvider() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testGetPreSignKeys() {
        assertNotNull("Should find presign RSA key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_RSA_PRIV).getPublic()));
        assertNotNull("Should find presign secp256r1 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV).getPublic()));
        assertNotNull("Should find presign secp384r1 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV).getPublic()));
        assertNotNull("Should find presign Ed25519 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_ED25519,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED25519_PRIV).getPublic()));
        assertNotNull("Should find presign Ed448 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_ED448,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_ED448_PRIV).getPublic()));
        assertNotNull("Should find presign Falcon512 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_FALCON512,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON512_PRIV).getPublic()));
        assertNotNull("Should find presign Falcon1024 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_FALCON1024,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_FALCON1024_PRIV).getPublic()));
        assertNotNull("Should find presign ML-DSA-44 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_MLDSA44,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_44_PRIV).getPublic()));
        assertNotNull("Should find presign ML-DSA-65 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_MLDSA65,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_65_PRIV).getPublic()));
        assertNotNull("Should find presign ML-DSA-87 key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_MLDSA87,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_87_PRIV).getPublic()));
        assertNotNull("Should find presign LMS key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.KEYALGORITHM_LMS,
                        KeyTools.getPublicKeyFromBytes(Base64.decode(CAConstants.PRESIGN_VALIDATION_KEY_LMS_PUB))));
    }

    @Test
    public void testP256Presign() {
        final PublicKey preSignKey = CAConstants.getPreSignPublicKey(
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA,
                KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_EC_SECP256R1_PRIV).getPublic());
        final byte[] encodedKey = preSignKey.getEncoded();
        final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedKey));
        final AlgorithmIdentifier algorithmIdentifier = spki.getAlgorithm();
        final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algorithmIdentifier.getParameters();
        log.info("OID: " + oid);
        // http://oid-info.com/get/1.2.840.10045.3.1.7
        assertEquals("presign key uses wrong curve (expected P-256)", "1.2.840.10045.3.1.7", oid.toString());
    }

    @Test
    public void testP384Presign() {
        final PublicKey preSignKey = CAConstants.getPreSignPublicKey(
                AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA,
                KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_EC_SECP384R1_PRIV).getPublic());
        final byte[] encodedKey = preSignKey.getEncoded();
        final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedKey));
        final AlgorithmIdentifier algorithmIdentifier = spki.getAlgorithm();
        final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algorithmIdentifier.getParameters();
        log.info("OID: " + oid);
        // http://oid-info.com/get/1.3.132.0.34
        assertEquals("presign key uses wrong curve (expected P-384)", "1.3.132.0.34", oid.toString());
    }

    @Test
    public void testMLDSA44Presign() {
        final PublicKey preSignKey = CAConstants.getPreSignPublicKey(
                AlgorithmConstants.SIGALG_MLDSA44,
                KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_MLDSA_44_PRIV).getPublic());
        final byte[] encodedKey = preSignKey.getEncoded();
        final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedKey));
        final AlgorithmIdentifier algorithmIdentifier = spki.getAlgorithm();
        log.info("OID: " + algorithmIdentifier.getAlgorithm());
        assertEquals("presign key uses wrong algorithm (expected ML-DSA-44)", NISTObjectIdentifiers.id_ml_dsa_44.getId(), algorithmIdentifier.getAlgorithm().getId());
    }

    @Test
    public void testLMSPresign() {
        final PublicKey preSignKey = CAConstants.getPreSignPublicKey(
                AlgorithmConstants.KEYALGORITHM_LMS,
                KeyTools.getPublicKeyFromBytes(Base64.decode(CAConstants.PRESIGN_VALIDATION_KEY_LMS_PUB)));
        final byte[] encodedKey = preSignKey.getEncoded();
        final SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encodedKey));
        final AlgorithmIdentifier algorithmIdentifier = spki.getAlgorithm();
        log.info("OID: " + algorithmIdentifier.getAlgorithm());
        assertEquals("presign key uses wrong algorithm (expected LMS)", PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), algorithmIdentifier.getAlgorithm().getId());
    }

}
