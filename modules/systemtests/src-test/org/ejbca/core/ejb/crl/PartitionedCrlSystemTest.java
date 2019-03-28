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
package org.ejbca.core.ejb.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests certificate generation and publishing with partitioned CRLs
 * 
 * @version $Id$
 */
public class PartitionedCrlSystemTest {

    private static final Logger log = Logger.getLogger(PartitionedCrlSystemTest.class);

    private static final String TEST_NAME = "PartitionedCrlSystemTest";
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(TEST_NAME);

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateSessionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private static final PublisherProxySessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private static final String TEST_CA = TEST_NAME + "_CA";
    private static final String TEST_PUBLISHER = TEST_NAME + "_PUBLISHER";
    private static final String TEST_ENDENTITY = TEST_NAME + "_ENDENTITY";
    private static final String TEST_CERTPROFILE = TEST_NAME + "_CP";
    private static final String TEST_EEPROFILE = TEST_NAME + "_EEP";

    private static final String CA_DN = "CN=TestCA with CRL Partitioning,OU=QA,O=TEST,C=SE";
    private static final String CERT_DN = "CN=Partitioned CRL User,OU=QA,O=TEST,C=SE";

    private static final String CRLDP_TEMPLATE_URI = "http://crl*.example.com/TestCRL*.crl";
    private static final String CRLDP_MAIN_URI = "http://crl.example.com/TestCRL.crl";
    private static final String CRLDP_PARTITION1_URI = "http://crl1.example.com/TestCRL1.crl";
    private static final String CRLDP_PARTITION2_URI = "http://crl2.example.com/TestCRL2.crl";

    private static final String DELTACRLDP_TEMPLATE_URI = "http://crl*.example.com/TestDeltaCRL*.crl";
    private static final String DELTACRLDP_MAIN_URI = "http://crl.example.com/TestDeltaCRL.crl";
    private static final String DELTACRLDP_PARTITION1_URI = "http://crl1.example.com/TestDeltaCRL1.crl";
    private static final String DELTACRLDP_PARTITION2_URI = "http://crl2.example.com/TestDeltaCRL2.crl";

    private static KeyPair userKeyPair;
    private static int caId, certificateProfileId, endEntityProfileId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass");
        cleanupClass();
        CaTestCase.createTestCA(TEST_CA, 1024, CA_DN, CAInfo.SELFSIGNED, null);
        caId = caSession.getCAInfo(admin, TEST_CA).getCAId();
        final GeneralPurposeCustomPublisher publisher = new GeneralPurposeCustomPublisher();
        publisher.setDescription("Used in system test");
        publisher.setName(TEST_PUBLISHER);
        publisher.setOnlyUseQueue(true);
        publisher.setUseQueueForCertificates(true);
        publisher.setUseQueueForCRLs(true);
        publisher.setKeepPublishedInQueue(false);
        final int publisherId = publisherSession.addPublisher(admin, TEST_PUBLISHER, publisher);
        userKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        final CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProf.setUseCRLDistributionPoint(true);
        certProf.setUseDefaultCRLDistributionPoint(true);
        certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TEST_CERTPROFILE, certProf);
        final EndEntityProfile eeProf = new EndEntityProfile(false);
        eeProf.setAvailableCAs(new ArrayList<>(Collections.singleton(caId)));
        eeProf.setAvailableCertificateProfileIds(new ArrayList<>(Collections.singleton(certificateProfileId)));
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_EEPROFILE, eeProf);
        // Set common settings to all tests CA
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_CA);
        caInfo.setUseCrlDistributionPointOnCrl(true);
        caInfo.setCrlDistributionPointOnCrlCritical(true);
        caInfo.setUseCRLNumber(true);
        caInfo.setCRLIssueInterval(20);
        caInfo.setDeltaCRLPeriod(10);
        caInfo.setCRLPublishers(new ArrayList<>(Collections.singleton(publisherId)));
        caAdminSession.editCA(admin, caInfo);
        log.trace("<beforeClass");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        log.trace(">afterClass");
        cleanupClass();
        log.trace("<afterClass");
    }

    private static void cleanupClass() throws Exception {
        log.trace(">cleanup");
        cleanupTestCase();
        CaTestCase.removeTestCA(TEST_CA);
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_EEPROFILE);
        certificateProfileSession.removeCertificateProfile(admin, TEST_CERTPROFILE);
        publisherSession.removePublisherInternal(admin, TEST_PUBLISHER);
        log.trace("<cleanup");
    }

    private static void cleanupTestCase() throws AuthorizationDeniedException {
        internalCertificateSessionSession.removeCertificatesBySubject(CERT_DN);
        internalCertificateSessionSession.removeCRLs(admin, CA_DN);
        final int publisherId = publisherSession.getPublisherId(TEST_PUBLISHER);
        if (publisherId != 0) {
            for (final PublisherQueueData queueEntry : publisherQueueSession.getPendingEntriesForPublisher(publisherId)) {
                publisherQueueSession.removeQueueData(queueEntry.getPk());
            }
        }
    }

    @After
    public void after() throws AuthorizationDeniedException {
        cleanupTestCase();
    }

    @Test
    public void basicTest() throws Exception {
        log.trace(">basicTest");
        // Given
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_CA);
        caInfo.setUsePartitionedCrl(false);
        caInfo.setDefaultCRLDistPoint(CRLDP_MAIN_URI);
        caInfo.setCADefinedFreshestCRL(DELTACRLDP_MAIN_URI);
        caInfo.setCrlPartitions(0);
        caInfo.setRetiredCrlPartitions(0);
        caAdminSession.editCA(admin, caInfo);
        // When
        final Certificate cert = issueCertificate(); // should appear on CRL
        final Certificate deltaCert = issueCertificate(); // should appear on Delta CRL
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000)); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        revokeCertificate(deltaCert, new Date());
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        assertEquals("Wrong CRL DP in first certificate.", CRLDP_MAIN_URI, CertTools.getCrlDistributionPoint(cert));
        assertEquals("Wrong CRL DP in second certificate.", CRLDP_MAIN_URI, CertTools.getCrlDistributionPoint(deltaCert));
        final X509CRL crl = getLatestCrl(CertificateConstants.NO_CRL_PARTITION, false);
        final X509CRL deltaCrl = getLatestCrl(CertificateConstants.NO_CRL_PARTITION, true);
        assertEquals("Wrong Issuing Distribution Point in CRL.", Collections.singletonList(CRLDP_MAIN_URI), CertTools.getCrlDistributionPoints(crl));
        assertEquals("Wrong Issuing Distribution Point in Delta CRL.", Collections.singletonList(CRLDP_MAIN_URI), CertTools.getCrlDistributionPoints(deltaCrl));
        assertInclusionOnCrl(crl, deltaCrl, cert, deltaCert);
        assertPublisherQueueData(Arrays.asList(crl, deltaCrl));
        log.trace("<basicTest");
    }

    private void revokeCertificate(final Certificate cert, final Date revocationDate) throws CertificateRevokeException, AuthorizationDeniedException {
        internalCertificateSessionSession.setRevokeStatus(admin, cert, revocationDate, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
    }

    private Certificate issueCertificate() throws Exception {
        final EndEntityInformation endEntity = new EndEntityInformation();
        endEntity.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        endEntity.setUsername(TEST_ENDENTITY);
        endEntity.setPassword("foo123");
        endEntity.setDN(CERT_DN);
        endEntity.setCAId(caId);
        endEntity.setCertificateProfileId(certificateProfileId);
        endEntity.setEndEntityProfileId(endEntityProfileId);
        endEntity.setTokenType(EndEntityConstants.TOKEN_USERGEN);

        final SimpleRequestMessage req = new SimpleRequestMessage(userKeyPair.getPublic(), TEST_ENDENTITY, "foo123");
        req.setIssuerDN(CA_DN);
        req.setRequestDN(CERT_DN);

        final X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(admin, endEntity, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        assertNotNull("Failed to get response", resp);
        assertNotNull("No certificate was returned. " + resp.getFailText(), resp.getCertificate());
        return resp.getCertificate();
    }

    private X509CRL getLatestCrl(final int crlPartitionIndex, final boolean deltaCrl) throws CRLException {
        final byte[] crl = crlStoreSession.getLastCRL(CA_DN, crlPartitionIndex, deltaCrl);
        final String crlDescription = (deltaCrl ? "Delta CRL" : "Base CRL") + " for partition " + crlPartitionIndex;
        assertNotNull(crlDescription + " was not created", crl);
        log.debug("Fingerprint for " + crlDescription + " is: " + CertTools.getFingerprintAsString(crl));
        return CertTools.getCRLfromByteArray(crl);
    }

    private void assertInclusionOnCrl(final X509CRL crl, final X509CRL deltaCrl, final Certificate cert, final Certificate deltaCert) {
        assertTrue("First certificate should be revoked on Base CRL", crl.isRevoked(cert));
        assertFalse("Second certificate should NOT be revoked on Base CRL", crl.isRevoked(deltaCert));
        assertFalse("First certificate should NOT be revoked on Delta CRL", deltaCrl.isRevoked(cert));
        assertTrue("Second certificate should be revoked on Delta CRL", deltaCrl.isRevoked(deltaCert));
    }

    private void assertPublisherQueueData(final Collection<X509CRL> crls) {
        final int publisherId = publisherSession.getPublisherId(TEST_PUBLISHER);
        final Collection<PublisherQueueData> queue = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        assertEquals("Wrong number of entries in publisher queue.", crls.size(), queue.size());
        final HashSet<String> remainingFingerprints = new HashSet<>();
        for (final X509CRL crl : crls) {
            remainingFingerprints.add(CertTools.getFingerprintAsString(crl));
        }
        for (final PublisherQueueData queueEntry : queue) {
            final String fingerprint = queueEntry.getFingerprint();
            assertTrue("Missing publisher queue entry for CRL with fingerprint " + fingerprint,remainingFingerprints.remove(fingerprint));
        }
        assertEquals("Some CRLs were not found in the publisher queue.", 0, remainingFingerprints.size()); // this should never happen
    }
}
