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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;

import java.security.KeyPair;
import java.security.Security;

import org.cesecore.certificates.certificate.cvc.CvCertificateUtility;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.certificate.CertificateImplementationRegistry;

/**
 *
 */
public class AlgorithmToolsCvcTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new CvCertificateUtility());
        Security.addProvider(new CVCProvider());   
    }
    
    @Test
    public void testCertSignatureAlgorithmAsString() throws Exception {
        KeyPair keyPair = KeyTools.genKeys("2048", "RSA"); // 2048 needed for MGF1 with SHA512

        // CVC + RSA
        CAReferenceField caRef = new CAReferenceField("SE", "CAREF001", "00000");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "HOLDERRE", "00000");
        CardVerifiableCertificate cvsha1 = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSA", AuthorizationRoleEnum.IS));
        CardVerifiableCertificate cvsha256 = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithRSA", AuthorizationRoleEnum.IS));
        CardVerifiableCertificate cvsha1mgf = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithRSAAndMGF1", AuthorizationRoleEnum.IS));
        CardVerifiableCertificate cvsha256mgf = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithRSAAndMGF1", AuthorizationRoleEnum.IS));
        assertEquals("SHA1WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(cvsha1));
        assertEquals("SHA256WITHRSA", CertTools.getCertSignatureAlgorithmNameAsString(cvsha256));
        assertEquals("SHA1WITHRSAANDMGF1", CertTools.getCertSignatureAlgorithmNameAsString(cvsha1mgf));
        assertEquals("SHA256WITHRSAANDMGF1", CertTools.getCertSignatureAlgorithmNameAsString(cvsha256mgf));

        assertEquals("SHA1WithRSA", AlgorithmTools.getSignatureAlgorithm(cvsha1));
        assertEquals("SHA256WithRSA", AlgorithmTools.getSignatureAlgorithm(cvsha256));
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(cvsha1mgf));
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, AlgorithmTools.getSignatureAlgorithm(cvsha256mgf));


        keyPair = KeyTools.genKeys("prime192v1", "ECDSA");
        // CVC + ECC
        CardVerifiableCertificate cvsha1ecc = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", AuthorizationRoleEnum.IS));
        CardVerifiableCertificate cvsha224ecc = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA224WithECDSA", AuthorizationRoleEnum.IS));
        CardVerifiableCertificate cvsha256ecc = new CardVerifiableCertificate(CertificateGenerator.
                createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA256WithECDSA", AuthorizationRoleEnum.IS));
        assertEquals("SHA1WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(cvsha1ecc));
        assertEquals("SHA224WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(cvsha224ecc));
        assertEquals("SHA256WITHECDSA", CertTools.getCertSignatureAlgorithmNameAsString(cvsha256ecc));

        assertEquals("SHA1withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha1ecc));
        assertEquals("SHA224withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha224ecc));
        assertEquals("SHA256withECDSA", AlgorithmTools.getSignatureAlgorithm(cvsha256ecc));

        
    }

}
