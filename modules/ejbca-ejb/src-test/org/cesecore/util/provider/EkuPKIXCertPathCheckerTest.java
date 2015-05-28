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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test EKU validation.
 * 
 * @version $Id$
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

    final List<String> ekusEmpty = Arrays.asList(new String[]{ });
    final List<String> ekus2 = Arrays.asList(new String[]{ KeyPurposeId.id_kp_emailProtection.getId() });
    final List<String> ekus3 = Arrays.asList(new String[]{ KeyPurposeId.id_kp_codeSigning.getId(), KeyPurposeId.id_kp_smartcardlogon.getId() });
    final List<String> ekus4 = Arrays.asList(new String[]{ KeyPurposeId.id_kp_ipsecEndSystem.getId(), KeyPurposeId.id_kp_serverAuth.getId() });
    final List<String> ekus5 = Arrays.asList(new String[]{ KeyPurposeId.id_kp_serverAuth.getId() });
    final List<String> ekus6 = Arrays.asList(new String[]{ KeyPurposeId.id_kp_clientAuth.getId(), KeyPurposeId.id_kp_codeSigning.getId(), KeyPurposeId.id_kp_emailProtection.getId() });

    @Test
    public void testNoEkuInCert() throws Exception {
        log.trace(">testNoEkuInCert");
        /*
         * When no EKU is present in the certificate, the PKIXCertPathChecker should never be invoked.
         * This just documents the actual behavior in such a case.
         */
        assertTrue(validateCert(keyPair, LEAF, null, null));
        assertFalse(validateCert(keyPair, CA, null, null));
        assertTrue(validateCert(keyPair, LEAF, null, ekusEmpty));
        assertFalse(validateCert(keyPair, CA, null, ekusEmpty));
        assertFalse(validateCert(keyPair, LEAF, null, ekus2));
        assertFalse(validateCert(keyPair, CA, null, ekus2));
        assertFalse(validateCert(keyPair, LEAF, null, ekus3));
        assertFalse(validateCert(keyPair, CA, null, ekus3));
        log.trace("<testNoEkuInCert");
    }

    @Test
    public void testEmptyCriticalEkuInCert() throws Exception {
        /*
         * When an empty EKU is present in the certificate, the PKIXCertPathChecker will perform the check for required.
         * However, it is not clear if it should be invoked in such a case.
         */
        assertTrue(validateCert(keyPair, LEAF, ekusEmpty, null));
        assertFalse(validateCert(keyPair, CA, ekusEmpty, null));
        assertTrue(validateCert(keyPair, LEAF, ekusEmpty, ekusEmpty));
        assertFalse(validateCert(keyPair, CA, ekusEmpty, ekusEmpty));
        assertFalse(validateCert(keyPair, LEAF, ekusEmpty, ekus2));
        assertFalse(validateCert(keyPair, CA, ekusEmpty, ekus2));
        assertFalse(validateCert(keyPair, LEAF, ekusEmpty, ekus3));
        assertFalse(validateCert(keyPair, CA, ekusEmpty, ekus3));
    }

    @Test
    public void testCriticalEkuWithOneInCert() throws Exception {
        assertTrue(validateCert(keyPair, LEAF, ekus5, null));
        assertFalse(validateCert(keyPair, CA, ekus5, null));
        assertTrue(validateCert(keyPair, LEAF, ekus5, ekusEmpty));
        assertFalse(validateCert(keyPair, CA, ekus5, ekusEmpty));
        assertTrue(validateCert(keyPair, LEAF, ekus5, ekus5));
        assertFalse(validateCert(keyPair, CA, ekus5, ekus5));
        assertFalse(validateCert(keyPair, LEAF, ekus5, ekus4));
        assertFalse(validateCert(keyPair, CA, ekus5, ekus4));
        assertFalse(validateCert(keyPair, LEAF, ekus5, ekus6));
        assertFalse(validateCert(keyPair, CA, ekus5, ekus6));
    }

    @Test
    public void testCriticalEkuWithTwoInCert() throws Exception {
        assertTrue(validateCert(keyPair, LEAF, ekus4, null));
        assertFalse(validateCert(keyPair, CA, ekus4, null));
        assertTrue(validateCert(keyPair, LEAF, ekus4, ekusEmpty));
        assertFalse(validateCert(keyPair, CA, ekus4, ekusEmpty));
        assertTrue(validateCert(keyPair, LEAF, ekus4, ekus5));
        assertFalse(validateCert(keyPair, CA, ekus4, ekus5));
        assertTrue(validateCert(keyPair, LEAF, ekus4, ekus4));
        assertFalse(validateCert(keyPair, CA, ekus4, ekus4));
        assertFalse(validateCert(keyPair, LEAF, ekus4, ekus6));
        assertFalse(validateCert(keyPair, CA, ekus4, ekus6));
    }

    /** @return true if the extendedKeyUsage was accepted */
    private boolean validateCert(KeyPair keyPair, boolean isCa, List<String> actualOids, List<String> requiredOids) throws Exception {
        final long now = System.currentTimeMillis();
        final List<Extension> additionalExtensions = new ArrayList<Extension>();
        if (actualOids!=null) {
            List<KeyPurposeId> actual = new ArrayList<KeyPurposeId>();
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
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, isCa, ku, null, null, BouncyCastleProvider.PROVIDER_NAME, true, additionalExtensions);
        final PKIXCertPathChecker pkixCertPathChecker = new EkuPKIXCertPathChecker(requiredOids);
        final Collection<String> unresolvedCritExts = new ArrayList<String>(Arrays.asList(new String[] {Extension.extendedKeyUsage.getId()}));
        pkixCertPathChecker.check(cert, unresolvedCritExts);
        return !unresolvedCritExts.contains(Extension.extendedKeyUsage.getId());
    }
}
