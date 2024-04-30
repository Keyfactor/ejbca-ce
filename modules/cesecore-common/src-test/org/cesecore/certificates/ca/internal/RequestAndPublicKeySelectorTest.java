/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 * Unit tests for the RequestAndPublicKeySelector class
 */
public class RequestAndPublicKeySelectorTest {

    @Rule
    public TestName testName = new TestName();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testExtractAlternativeKey()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, OperatorCreationException, IOException {
        final String subjectDn = "CN=" + testName.getMethodName();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("P-256"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyPairGenerator alternativeKeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM,
                BouncyCastleProvider.PROVIDER_NAME);
        alternativeKeyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair alternativeKeyPair = alternativeKeyPairGenerator.generateKeyPair();

        ContentSigner altSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_DILITHIUM2).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(alternativeKeyPair.getPrivate());

        JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                keyPair.getPublic());

        PKCS10CertificationRequest pkcs10CertificationRequest = jcaPKCS10CertificationRequestBuilder
                .build(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()), alternativeKeyPair.getPublic(), altSigner);

        assertTrue("No alternative key was included in request", pkcs10CertificationRequest.hasAltPublicKey());
        PKCS10RequestMessage request = new PKCS10RequestMessage(pkcs10CertificationRequest.toASN1Structure().getEncoded());
        
        RequestAndPublicKeySelector requestAndPublicKeySelector = new RequestAndPublicKeySelector(request, null, null, null);
        
        assertEquals("Alterative public key was not correctly extracted from request.", alternativeKeyPair.getPublic(), requestAndPublicKeySelector.getAlternativePublicKey());

    }

}
