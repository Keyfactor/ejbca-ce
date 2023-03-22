package org.ejbca.core.ejb.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
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
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.DummyCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

public class InvalidityDateCrlSystemTest {

    private static final Logger log = Logger.getLogger(InvalidityDateCrlSystemTest.class);

    private static final String TEST_NAME = "InvalidityDateCrlSystemTest";
    private static final String TEST_CA = TEST_NAME + "_CA";
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(TEST_NAME);
    private static final String CA_COMMONNAME = "TestCA with Invalidity Date";
    private static final String CA_DN = "CN=" + CA_COMMONNAME + ",OU=QA,O=TEST,C=SE";
    private static final String TEST_CRL_PUBLISHER = TEST_NAME + "_CRL_PUBLISHER";
    private static final String TEST_CERTIFICATE_PUBLISHER = TEST_NAME + "_CERTIFICATE_PUBLISHER";
    private static final String TEST_CERTPROFILE = TEST_NAME + "_CP";
    private static final String TEST_EEPROFILE = TEST_NAME + "_EEP";
    private static final String TEST_ENDENTITY = TEST_NAME + "_ENDENTITY";
    private static final String CERT_DN = "CN=Invalidity Date User,OU=QA,O=TEST,C=SE";

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final PublisherProxySessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateSessionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static final PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private static final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private static final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);


    private static KeyPair userKeyPair;
    private static int caId, certificateProfileId, endEntityProfileId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass");
        cleanupClass();
        CaTestCase.createTestCA(TEST_CA, 1024, CA_DN, CAInfo.SELFSIGNED, null);
        caId = caSession.getCAInfo(admin, TEST_CA).getCAId();
        // Publishers. These will never run, but will accept CRLs/certificates in the queue.
        final int crlPublisherId = addPublisher(TEST_CRL_PUBLISHER);
        final int certPublisherId = addPublisher(TEST_CERTIFICATE_PUBLISHER);
        // Key pair
        userKeyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        // Certificate profile for user certificates
        final CertificateProfile certProf = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProf.setUseCRLDistributionPoint(true);
        certProf.setUseDefaultCRLDistributionPoint(true);
        certProf.setAvailableCAs(Collections.singletonList(caId));
        certProf.setPublisherList(new ArrayList<>(Collections.singleton(certPublisherId)));
        certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TEST_CERTPROFILE, certProf);
        //EE profile for user certificates
        final EndEntityProfile eeProf = new EndEntityProfile(false);
        eeProf.setAvailableCAs(new ArrayList<>(Collections.singleton(caId)));
        eeProf.setAvailableCertificateProfileIds(new ArrayList<>(Collections.singleton(certificateProfileId)));
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_EEPROFILE, eeProf);
        // Set common settings to all tests CA
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(admin, TEST_CA);
        caInfo.setUseCrlDistributionPointOnCrl(true);
        caInfo.setCrlDistributionPointOnCrlCritical(true);
        caInfo.setCRLPublishers(new ArrayList<>(Collections.singleton(crlPublisherId)));
        caInfo.setAllowInvalidityDate(true);
        caInfo.setUseUserStorage(false); // avoid having to create end entities
        caAdminSession.editCA(admin, caInfo);
        internalCertificateSessionSession.removeCRLs(admin, CA_DN); // remove initial CRLs
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
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_EEPROFILE);
        certificateProfileSession.removeCertificateProfile(admin, TEST_CERTPROFILE);
        CaTestCase.removeTestCA(TEST_CA);
        publisherSession.removePublisherInternal(admin, TEST_CRL_PUBLISHER);
        publisherSession.removePublisherInternal(admin, TEST_CERTIFICATE_PUBLISHER);
        log.trace("<cleanup");
    }

    @After
    public void after() throws AuthorizationDeniedException {
        cleanupTestCase();
    }

    private static void cleanupTestCase() throws AuthorizationDeniedException {
        internalCertificateSessionSession.removeCertificatesBySubject(CERT_DN);
        internalCertificateSessionSession.removeCRLs(admin, CA_DN);
        publisherQueueSession.removePublisherQueueEntries(TEST_CRL_PUBLISHER);
        publisherQueueSession.removePublisherQueueEntries(TEST_CERTIFICATE_PUBLISHER);
    }

    /**
     * Test CRL generation and publisher queuing without CRL invalidity date:
     * <ol>
     * <li>Issue certificate, revoke, create Base CRL.
     * <li>Issue another certificate, revoke, create Delta CRL
     * </ol>
     * For both steps, we expect a CRL with the correct contents, and that the CRLs and certificates are placed in the publisher queue.
     * Invalidity date is empty
     */
    @Test
    public void generateAndPublishCrlNoInvalidityDate() throws Exception {
        log.trace(">generateAndPublishCrlNoInvalidityDate");
        // Given
        final Certificate cert = issueCertificate(); // should appear on CRL
        final Certificate deltaCert = issueCertificate(); // should appear on Delta CRL
        // When
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), null); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        revokeCertificate(deltaCert, new Date(), null);
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        final X509CRL crl = getLatestCrl(false);
        final X509CRL deltaCrl = getLatestCrl(true);
        X509CRLEntry crlRevokedCertificate = crl.getRevokedCertificate((X509Certificate) cert);
        Assert.assertNull("Unexpected invalidity date in crl", crlRevokedCertificate.getExtensionValue(Extension.invalidityDate.getId()));
        X509CRLEntry crlDeltaCertificate = deltaCrl.getRevokedCertificate((X509Certificate) deltaCert);
        Assert.assertNull("Unexpected invalidity date in delta crl", crlDeltaCertificate.getExtensionValue(Extension.invalidityDate.getId()));

        log.trace("<generateAndPublishCrlNoInvalidityDate");
    }

    /**
     * Test CRL generation and publisher queuing with CRL invalidity date:
     * <ol>
     * <li>Issue certificate, revoke with  Invalidity date, create Base CRL .
     * <li>Issue another certificate, revoke with  Invalidity date, create Delta CRL
     * </ol>
     * For both steps, we expect a CRL with the correct contents, and that the CRLs and certificates are placed in the publisher queue.
     * Invalidity date is set
     */
    @Test
    public void generateAndPublishCrlWithInvalidityDate() throws Exception {
        log.trace(">generateAndPublishCrlWithInvalidityDate");
        // Given
        final Certificate cert = issueCertificate(); // should appear on CRL
        final Certificate deltaCert = issueCertificate(); // should appear on Delta CRL
        // When
        Date invalidityDate = new Date(new Date().getTime() - 8 * 60 * 1000);
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), invalidityDate); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        Date invalidityDate2 = new Date(new Date().getTime() - 5 * 60 * 1000);
        revokeCertificate(deltaCert, new Date(), invalidityDate2);
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        final X509CRL crl = getLatestCrl(false);
        final X509CRL deltaCrl = getLatestCrl(true);
        X509CRLEntry crlRevokedCertificate = crl.getRevokedCertificate((X509Certificate) cert);
        byte[] extensionValue = crlRevokedCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Invalidity date extention should be present in crl record", extensionValue);
        X509CRLEntry crlDeltaCertificate = deltaCrl.getRevokedCertificate((X509Certificate) deltaCert);
        byte[] deltaCertificateExtensionValue = crlDeltaCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Invalidity date extention should be present in crl record", deltaCertificateExtensionValue);

        ASN1GeneralizedTime time = CrlExtensions.extractInvalidityDate(crlRevokedCertificate);
        assertEquals("Certificate invalidity date not as expected", invalidityDate.toString(), time.getDate().toString());
        ASN1GeneralizedTime time2 = CrlExtensions.extractInvalidityDate(crlDeltaCertificate);
        assertEquals("Certificate invalidity date not as expected", invalidityDate2.toString(), time2.getDate().toString());

        log.trace("<generateAndPublishCrlWithInvalidityDate");
    }

    /**
     * Test CRL generation and publisher queuing with updated invalidity date:
     * <ol>
     * <li>Issue certificate, revoke no invalidity date, create Base CRL, set Invalidity date, create Delta CRL,
     * </ol>
     * For both steps, we expect a CRL with the correct contents, and that the CRLs and certificates are placed in the publisher queue.
     * Invalidity date is present in deltaCrl for first certificate
     */
    @Test
    public void generateAndPublishCrlWithInvalidityDateSetAfterRevocation() throws Exception {
        log.trace(">generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
        // Given
        final Certificate cert = issueCertificate(); // should appear on CRL
        // When
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), null); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        Date invalidityDate = new Date(new Date().getTime() - 8 * 60 * 1000);
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), invalidityDate); // backdate revocation by 5 minutes
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        final X509CRL crl = getLatestCrl(false);
        final X509CRL deltaCrl = getLatestCrl(true);
        X509CRLEntry crlRevokedCertificate = crl.getRevokedCertificate((X509Certificate) cert);
        Assert.assertNull("Unexpected invalidity date in crl", crlRevokedCertificate.getExtensionValue(Extension.invalidityDate.getId()));
        X509CRLEntry crlDeltaCertificate = deltaCrl.getRevokedCertificate((X509Certificate) cert);
        Assert.assertNotNull("Delta crl should contain changed certificate", crlDeltaCertificate);
        byte[] extensionValue = crlDeltaCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Invalidity date extention should be present in crl record", extensionValue);

        ASN1GeneralizedTime time = CrlExtensions.extractInvalidityDate(crlDeltaCertificate);
        assertEquals("Certificate invalidity date not as expected", invalidityDate.toString(), time.getDate().toString());

        log.trace("<generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
    }

    /**
     * Test CRL generation and publisher queuing with changed  invalidity date:
     * <ol>
     * <li>Issue certificate, revoke with invalidity date, create Base CRL, change Invalidity date.
     * <li>Issue another certificate, revoke, create Delta CRL,
     * </ol>
     * For both steps, we expect a CRL with the correct contents, and that the CRLs and certificates are placed in the publisher queue.
     * Invalidity date not set in Base CRL, delta CRL has updated Invalidity date Value
     */
    @Test
    public void generateAndPublishCrlWithInvalidityDateSetOnCreationAndChanged() throws Exception {
        log.trace(">generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
        // Given
        final Certificate cert = issueCertificate(); // should appear on CRL
        final Certificate secondCert = issueCertificate(); // should appear on Delta CRL
        // When
        Date invalidityDate = new Date(new Date().getTime() - 8 * 60 * 1000);
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), invalidityDate); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        Date changedInvalidityDate = new Date(new Date().getTime() - 16 * 60 * 1000);
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), changedInvalidityDate); // backdate revocation by 5 minutes
        revokeCertificate(secondCert, new Date(), null);
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        final X509CRL crl = getLatestCrl(false);
        final X509CRL deltaCrl = getLatestCrl(true);
        X509CRLEntry crlRevokedCertificate = crl.getRevokedCertificate((X509Certificate) cert);
        byte[] extensionValue = crlRevokedCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Invalidity date extention should be present in crl record", extensionValue);
        ASN1GeneralizedTime time = CrlExtensions.extractInvalidityDate(crlRevokedCertificate);
        assertEquals("Certificate invalidity date not as expected", invalidityDate.toString(), time.getDate().toString());

        X509CRLEntry crlDeltaCertificate = deltaCrl.getRevokedCertificate((X509Certificate) cert);
        X509CRLEntry crlDeltaSecondCertificate = deltaCrl.getRevokedCertificate((X509Certificate) secondCert);
        Assert.assertNotNull("Delta crl should contain changed certificate", crlDeltaCertificate);
        byte[] extensionValueChanged = crlDeltaCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Changed invalidity date extention should be present in crl record", extensionValueChanged);
        ASN1GeneralizedTime time2 = CrlExtensions.extractInvalidityDate(crlDeltaCertificate);
        assertEquals("Certificate invalidity date not as expected", changedInvalidityDate.toString(), time2.getDate().toString());

        Assert.assertNull("Unexpected invalidity date in crl", crlDeltaSecondCertificate.getExtensionValue(Extension.invalidityDate.getId()));
        log.trace("<generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
    }

    /**
     * Test CRL generation and publisher queuing with changed CRL invalidity date:
     * <ol>
     * <li>Issue certificate, revoke without invalidity date create Base CRL, change Invalidity date.
     * <li>Issue another certificate, revoke, create Delta CRL,
     * </ol>
     * For both steps, we expect a CRL with the correct contents, and that the CRLs and certificates are placed in the publisher queue.
     * Invalidity date is set in Base CRL, delta CRL has updated Invalidity date Value
     */
    @Test
    public void generateAndPublishCrlWithInvalidityDateSetAfterCreationAndChanged() throws Exception {
        log.trace(">generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
        // Given
        final Certificate cert = issueCertificate(); // should appear on CRL
        final Certificate secondCert = issueCertificate(); // should appear on Delta CRL
        // When
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), null); // backdate revocation by 5 minutes
        assertTrue("CRL generation failed", publishingCrlSession.forceCRL(admin, caId));
        Date invalidityDate = new Date(new Date().getTime() - 16 * 60 * 1000);
        revokeCertificate(cert, new Date(new Date().getTime() - 5*60*1000), invalidityDate); // backdate revocation by 5 minutes
        revokeCertificate(secondCert, new Date(), null);
        assertTrue("Delta CRL generation failed", publishingCrlSession.forceDeltaCRL(admin, caId));
        // Then
        final X509CRL crl = getLatestCrl(false);
        final X509CRL deltaCrl = getLatestCrl(true);
        X509CRLEntry crlRevokedCertificate = crl.getRevokedCertificate((X509Certificate) cert);
        Assert.assertNull("Unexpected invalidity date in crl", crlRevokedCertificate.getExtensionValue(Extension.invalidityDate.getId()));
        X509CRLEntry crlDeltaCertificate = deltaCrl.getRevokedCertificate((X509Certificate) cert);
        X509CRLEntry crlDeltaSecondCertificate = deltaCrl.getRevokedCertificate((X509Certificate) secondCert);
        Assert.assertNotNull("Delta crl should contain changed certificate", crlDeltaCertificate);
        byte[] extensionValueChanged = crlDeltaCertificate.getExtensionValue(Extension.invalidityDate.getId());
        Assert.assertNotNull("Invalidity date extention should be present in crl record", extensionValueChanged);
        ASN1GeneralizedTime time = CrlExtensions.extractInvalidityDate(crlDeltaCertificate);
        assertEquals("Certificate invalidity date not as expected", invalidityDate.toString(), time.getDate().toString());

        Assert.assertNull("Unexpected invalidity date in crl", crlDeltaSecondCertificate.getExtensionValue(Extension.invalidityDate.getId()));
        log.trace("<generateAndPublishCrlWithInvalidityDateSetAfterRevocation");
    }


    private static int addPublisher(final String name) throws PublisherExistsException, AuthorizationDeniedException {
        final CustomPublisherContainer publisher = new CustomPublisherContainer();
        publisher.setClassPath(DummyCustomPublisher.class.getName());
        publisher.setDescription("CRL publisher. Used in system test");
        publisher.setName(TEST_CRL_PUBLISHER);
        publisher.setOnlyUseQueue(true);
        publisher.setUseQueueForCertificates(true);
        publisher.setUseQueueForCRLs(true);
        publisher.setKeepPublishedInQueue(false);
        return publisherSession.addPublisher(admin, name, publisher);
    }

    /** Issues a certificate */
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

        final X509ResponseMessage resp = (X509ResponseMessage) signSession.createCertificate(admin, req,
                org.cesecore.certificates.certificate.request.X509ResponseMessage.class, endEntity);
        assertNotNull("Failed to get response", resp);
        assertNotNull("No certificate was returned. " + resp.getFailText(), resp.getCertificate());
        log.debug("Issued certificate with fingerprint " + CertTools.getFingerprintAsString(resp.getCertificate()));
        return resp.getCertificate();
    }

    /** Revokes a certificate. Supports backdated revocation. */
    private void revokeCertificate(final Certificate cert, final Date revocationDate, final Date invalidityDate) throws CertificateRevokeException, AuthorizationDeniedException {
        internalCertificateSessionSession.setRevokeStatus(admin, cert, revocationDate, invalidityDate, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        log.debug("Revoked certificate with fingerprint " + CertTools.getFingerprintAsString(cert));
    }

    /** Retrieves the latest Base or Delta CRL from database, and checks that it is the correct CRL */
    private X509CRL getLatestCrl(final boolean deltaCrl) throws CRLException {
        final byte[] crlBytes = crlStoreSession.getLastCRL(CA_DN, CertificateConstants.NO_CRL_PARTITION, deltaCrl);
        final String crlDescription = (deltaCrl ? "Delta CRL" : "Base CRL") + " for partition " + CertificateConstants.NO_CRL_PARTITION;
        assertNotNull(crlDescription + " was not created", crlBytes);
        log.debug("Fingerprint for " + crlDescription + " is: " + CertTools.getFingerprintAsString(crlBytes));
        final X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
        // Check that the CRL is correct
        assertEquals("deltaCRLIndicator extension precense is wrong.", deltaCrl, crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null);
        return crl;
    }

}
