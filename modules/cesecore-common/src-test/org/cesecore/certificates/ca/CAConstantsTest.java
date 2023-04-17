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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import java.security.PublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CAConstantsTest {
    private static final Logger log = Logger.getLogger(CAConstantsTest.class);

    @Before
    public void installBcProvider() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testGetPreSignKeys() {
        assertNotNull("Should find presign DSA key",
                CAConstants.getPreSignPublicKey(
                        AlgorithmConstants.SIGALG_SHA256_WITH_DSA,
                        KeyTools.getKeyPairFromPEM(CAConstants.PRESIGN_VALIDATION_KEY_DSA_PRIV).getPublic()));
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
}
