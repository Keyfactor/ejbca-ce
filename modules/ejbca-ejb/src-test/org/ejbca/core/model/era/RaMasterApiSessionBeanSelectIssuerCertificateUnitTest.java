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
package org.ejbca.core.model.era;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Unit tests for {@link RaMasterApiSessionBean#selectIssuerCertificate(Certificate, java.util.Collection, Date)}, which is used when
 * building the CA chain returned by e.g. the getLastCertChain web service call (issue #865).
 */
public class RaMasterApiSessionBeanSelectIssuerCertificateUnitTest {

    private static final String CA_DN = "CN=SelectIssuerCertificateUnitTest CA";
    private static final String OTHER_ROOT_DN = "CN=SelectIssuerCertificateUnitTest Other Root";
    private static final String EE_DN = "CN=SelectIssuerCertificateUnitTest EE";
    private static final long DAY = TimeUnit.DAYS.toMillis(1);

    private static KeyPair oldCaKeys;
    private static KeyPair newCaKeys;
    private static KeyPair otherRootKeys;
    private static KeyPair eeKeys;

    private final Date now = new Date();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        oldCaKeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        newCaKeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        otherRootKeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        eeKeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
    }

    private static X509Certificate cert(final String subjectDn, final String issuerDn, final KeyPair subjectKeys, final KeyPair issuerKeys,
            final Date notBefore, final Date notAfter, final boolean ca) throws Exception {
        return SimpleCertGenerator.forTESTCaCert()
                .setSubjectDn(subjectDn)
                .setIssuerDn(issuerDn)
                .setFirstDate(notBefore)
                .setLastDate(notAfter)
                .setIssuerPrivKey(issuerKeys.getPrivate())
                .setEntityPubKey(subjectKeys.getPublic())
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA)
                .setCa(ca)
                .setLdapOrder(true)
                .generateCertificate();
    }

    private X509Certificate caCert(final KeyPair keys, final long notBeforeOffsetDays, final long notAfterOffsetDays) throws Exception {
        return cert(CA_DN, CA_DN, keys, keys, new Date(now.getTime() + notBeforeOffsetDays * DAY),
                new Date(now.getTime() + notAfterOffsetDays * DAY), true);
    }

    private X509Certificate eeCert(final KeyPair caKeys) throws Exception {
        return cert(EE_DN, CA_DN, eeKeys, caKeys, new Date(now.getTime() - DAY), new Date(now.getTime() + 30 * DAY), false);
    }

    @Test
    public void renewedCaWithoutRekeyReturnsCurrentCaCertificateRegardlessOfOrder() throws Exception {
        // CA renewed without changing keys: both CA certificates verify the end entity certificate
        final X509Certificate oldCa = caCert(oldCaKeys, -3650, -1);   // expired yesterday
        final X509Certificate newCa = caCert(oldCaKeys, -100, 3650);  // current
        final X509Certificate ee = eeCert(oldCaKeys);
        assertEquals(newCa, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(oldCa, newCa), now));
        assertEquals(newCa, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(newCa, oldCa), now));
    }

    @Test
    public void renewedCaWithoutRekeyBothValidReturnsMostRecentlyIssued() throws Exception {
        // CA renewed before the old CA certificate expired
        final X509Certificate oldCa = caCert(oldCaKeys, -3650, 100);
        final X509Certificate newCa = caCert(oldCaKeys, -10, 3650);
        final X509Certificate ee = eeCert(oldCaKeys);
        assertEquals(newCa, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(oldCa, newCa), now));
        assertEquals(newCa, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(newCa, oldCa), now));
    }

    @Test
    public void renewedCaWithRekeyReturnsCertificateWithMatchingKey() throws Exception {
        final X509Certificate oldCa = caCert(oldCaKeys, -3650, 100);
        final X509Certificate newCa = caCert(newCaKeys, -10, 3650);
        final List<Certificate> candidates = Arrays.asList(newCa, oldCa);
        // Issued with the new key
        assertEquals(newCa, RaMasterApiSessionBean.selectIssuerCertificate(eeCert(newCaKeys), candidates, now));
        // Issued with the old key before the re-key, must still chain to the old CA certificate
        assertEquals(oldCa, RaMasterApiSessionBean.selectIssuerCertificate(eeCert(oldCaKeys), candidates, now));
    }

    @Test
    public void selfSignedCertificatePreferredOverCrossCertificateWithSameKey() throws Exception {
        final X509Certificate root = caCert(oldCaKeys, -100, 3650);
        // Cross certificate for the same CA (same subject and key), issued later by another root
        final X509Certificate cross = cert(CA_DN, OTHER_ROOT_DN, oldCaKeys, otherRootKeys, new Date(now.getTime() - DAY),
                new Date(now.getTime() + 365 * DAY), true);
        final X509Certificate ee = eeCert(oldCaKeys);
        assertEquals(root, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(cross, root), now));
        assertEquals(root, RaMasterApiSessionBean.selectIssuerCertificate(ee, Arrays.asList(root, cross), now));
    }

    @Test
    public void returnsNullWhenNoCandidateVerifies() throws Exception {
        final X509Certificate ca = caCert(newCaKeys, -10, 3650);
        assertNull(RaMasterApiSessionBean.selectIssuerCertificate(eeCert(oldCaKeys), Collections.singletonList(ca), now));
        assertNull(RaMasterApiSessionBean.selectIssuerCertificate(eeCert(oldCaKeys), Collections.emptyList(), now));
    }
}
