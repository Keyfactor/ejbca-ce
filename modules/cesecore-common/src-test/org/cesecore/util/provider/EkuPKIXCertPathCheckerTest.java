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
package org.cesecore.util.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test EKU validation.
 */
public class EkuPKIXCertPathCheckerTest {

    private static final Logger log = Logger.getLogger(EkuPKIXCertPathCheckerTest.class);
    private static KeyPair keyPair;
    private static final boolean CA = true;
    private static final boolean LEAF = false;
    
    @BeforeClass
    public static void beforeClass() throws InvalidAlgorithmParameterException {
        CryptoProviderTools.installBCProvider();
        keyPair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    final List<String> ekusEmpty = Arrays.asList();
    final List<String> ekus2 = Arrays.asList(KeyPurposeId.id_kp_emailProtection.getId());
    final List<String> ekus3 = Arrays.asList(KeyPurposeId.id_kp_codeSigning.getId(), KeyPurposeId.id_kp_smartcardlogon.getId());
    final List<String> ekus4 = Arrays.asList(KeyPurposeId.id_kp_ipsecEndSystem.getId(), KeyPurposeId.id_kp_serverAuth.getId());
    final List<String> ekus5 = Arrays.asList(KeyPurposeId.id_kp_serverAuth.getId());
    final List<String> ekus6 = Arrays.asList(KeyPurposeId.id_kp_clientAuth.getId(), KeyPurposeId.id_kp_codeSigning.getId(), KeyPurposeId.id_kp_emailProtection.getId());

    @Test
    public void testNoEkuInCert() throws Exception {
        log.trace(">testNoEkuInCert");
        /*
         * When no EKU is present in the certificate, the PKIXCertPathChecker should never be invoked.
         * This just documents the actual behavior in such a case.
         */
        assertTrue(validateCert(LEAF, false, null, null));
        assertFalse(validateCert(CA, false, null, null));
        assertTrue(validateCert(LEAF, false, null, ekusEmpty));
        assertFalse(validateCert(CA, false, null, ekusEmpty));
        assertFalse(validateCert(LEAF, false, null, ekus2));
        assertFalse(validateCert(CA, false, null, ekus2));
        assertFalse(validateCert(LEAF, false, null, ekus3));
        assertFalse(validateCert(CA, false, null, ekus3));
        assertTrue(validateCert(LEAF, true, null, null));
        assertFalse(validateCert(CA, true, null, null));
        assertTrue(validateCert(LEAF, true, null, ekusEmpty));
        assertFalse(validateCert(CA, true, null, ekusEmpty));
        assertFalse(validateCert(LEAF, true, null, ekus2));
        assertFalse(validateCert(CA, true, null, ekus2));
        assertFalse(validateCert(LEAF, true, null, ekus3));
        assertFalse(validateCert(CA, true, null, ekus3));
        log.trace("<testNoEkuInCert");
    }

    @Test
    public void testEmptyCriticalEkuInCert() throws Exception {
        /*
         * When an empty EKU is present in the certificate, the PKIXCertPathChecker will perform the check for required.
         * However, it is not clear if it should be invoked in such a case.
         */
        assertTrue(validateCert(LEAF, false, ekusEmpty, null));
        assertFalse(validateCert(CA, false, ekusEmpty, null));
        assertTrue(validateCert(LEAF, false, ekusEmpty, ekusEmpty));
        assertFalse(validateCert(CA, false, ekusEmpty, ekusEmpty));
        assertFalse(validateCert(LEAF, false, ekusEmpty, ekus2));
        try {
            validateCert(LEAF, true, ekusEmpty, ekus2);
            fail("Validation should have failed with missing EKUs");
        } catch (CertPathValidatorException e) {
            // NOPMD: this is what we expect
        }
        assertFalse(validateCert(CA, false, ekusEmpty, ekus2));
        assertFalse(validateCert(LEAF, false, ekusEmpty, ekus3));
        try {
            validateCert(LEAF, true, ekusEmpty, ekus3);
            fail("Validation should have failed with missing EKUs");
        } catch (CertPathValidatorException e) {
            // NOPMD: this is what we expect
        }
        assertFalse(validateCert(CA, false, ekusEmpty, ekus3));
    }

    @Test
    public void testCriticalEkuWithOneInCert() throws Exception {
        assertTrue(validateCert(LEAF, false, ekus5, null));
        assertFalse(validateCert(CA, false, ekus5, null));
        assertTrue(validateCert(LEAF, false, ekus5, ekusEmpty));
        assertFalse(validateCert(CA, false, ekus5, ekusEmpty));
        assertTrue(validateCert(LEAF, false, ekus5, ekus5));
        assertFalse(validateCert(CA, false, ekus5, ekus5));
        // Requires id_kp_ipsecEndSystem which is not present
        assertFalse(validateCert(LEAF, false, ekus5, ekus4));
        try {
            validateCert(LEAF, true, ekus5, ekus4);
            fail("Validation should have failed with missing EKUs");
        } catch (CertPathValidatorException e) {
            // NOPMD: this is what we expect
        }
        assertFalse(validateCert(CA, false, ekus5, ekus4));
        assertFalse(validateCert(LEAF, false, ekus5, ekus6));
        try {
            validateCert(LEAF, true, ekus5, ekus6);
            fail("Validation should have failed with missing EKUs");
        } catch (CertPathValidatorException e) {
            // NOPMD: this is what we expect
        }
        assertFalse(validateCert(CA, false, ekus5, ekus6));
    }

    @Test
    public void testCriticalEkuWithTwoInCert() throws Exception {
        assertTrue(validateCert(LEAF, false, ekus4, null));
        assertFalse(validateCert(CA, false, ekus4, null));
        assertTrue(validateCert(LEAF, false, ekus4, ekusEmpty));
        assertFalse(validateCert(CA, false, ekus4, ekusEmpty));
        assertTrue(validateCert(LEAF, false, ekus4, ekus5));
        assertFalse(validateCert(CA, false, ekus4, ekus5));
        assertTrue(validateCert(LEAF, false, ekus4, ekus4));
        assertFalse(validateCert(CA, false, ekus4, ekus4));
        assertFalse(validateCert(LEAF, false, ekus4, ekus6));
        try {
            validateCert(LEAF, true, ekus4, ekus6);
            fail("Validation should have failed with missing EKUs");
        } catch (CertPathValidatorException e) {
            // NOPMD: this is what we expect
        }
        assertFalse(validateCert(CA, false, ekus4, ekus6));
    }

    /** The method creates a certificate with a critical EKU and puts actualOids in there, then validates that all requiredOids are in the certificate using a EkuPKIXCertPathChecker
     * @return true if the extendedKeyUsage was accepted, either there was no EKU/actualOids, or all requiredOids are present
     * @throws CertPathValidatorException if throwOnFailure is true and the certificate has a critical EKU extension that does not contain all requiredOids 
     */
    private boolean validateCert(boolean isCa, boolean throwOnFailure, List<String> actualOids, List<String> requiredOids) throws Exception {
        final long now = System.currentTimeMillis();
        final List<Extension> additionalExtensions = new ArrayList<>();
        if (actualOids!=null) {
            List<KeyPurposeId> actual = new ArrayList<>();
            for (final String oid : actualOids) {
                actual.add(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid)));
            }
            final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(actual.toArray(new KeyPurposeId[0]));
            final ASN1Sequence seq = ASN1Sequence.getInstance(extendedKeyUsage.toASN1Primitive());
            final Extension extension = new Extension(Extension.extendedKeyUsage, true, seq.getEncoded());
            additionalExtensions.add(extension);
        }
        final int ku;
        if (isCa) {
            ku = X509KeyUsage.cRLSign|X509KeyUsage.keyCertSign;
        } else {
            ku = X509KeyUsage.digitalSignature|X509KeyUsage.keyEncipherment;
        }
        final X509Certificate cert = CertTools.genSelfCertForPurpose("CN=dummy", new Date(now-3600000L), new Date(now+3600000L), null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA, isCa, ku, null, null, BouncyCastleProvider.PROVIDER_NAME, true, additionalExtensions);
        final PKIXCertPathChecker pkixCertPathChecker = new EkuPKIXCertPathChecker(requiredOids);
        final Collection<String> unresolvedCritExts = new ArrayList<>(Arrays.asList(Extension.extendedKeyUsage.getId()));
        if (throwOnFailure) {
            pkixCertPathChecker.check(cert, unresolvedCritExts);
        } else {
            try {
                pkixCertPathChecker.check(cert, unresolvedCritExts);
            } catch (CertPathValidatorException e) {
                // NOPMD: we want to verify the unresolvedCritExts
            }
        }
        return !unresolvedCritExts.contains(Extension.extendedKeyUsage.getId());
    }
}
