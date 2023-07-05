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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.audit.EjbcaAuditorTestSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherTestSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.keys.KeyTools;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EndEntityManagementSessionAuditLogRedactTest extends CaTestCase {
    
    private static final Logger log = Logger.getLogger(EndEntityManagementSessionAuditLogRedactTest.class);
    
    private final static String DEVICE_NAME = IntegrityProtectedDevice.class.getSimpleName();
    private static final EjbcaAuditorTestSessionRemote ejbcaAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaAuditorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final NoConflictCertificateStoreSessionRemote noConflictCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(NoConflictCertificateStoreSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private final PublisherTestSessionRemote publisherTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final String THROWAWAY_CERT_PROFILE = EndEntityManagementSessionTest.class.getName()+"-ThrowAwayRevocationProfileRedactTest";
    private static final String THROWAWAY_PUBLISHER = EndEntityManagementSessionTest.class.getName()+"-ThrowAwayRevocationPublisherRedactTest";
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("EndEntityManagementSessionAuditLogRedactTest");
    private static final String REDACTED_EEP = "redacted_ee_profile";
    private static final String NON_REDACTED_EEP = "non_redacted_ee_profile";
    private static int redactedEepId;
    private static int nonRedactedEepId;
    private static final ArrayList<String> usernames = new ArrayList<>();
    
    private final int caId = getTestCAId();

    @Override
    public String getRoleName() {
        return "EndEntityManagementSessionAuditLogRedactTest";
    }
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        
        EndEntityProfile profile = new EndEntityProfile();
        profile.removeField(DnComponents.COMMONNAME, 0);
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.RFC822NAME);
        profile.setDescription("redact_me"); // enable redaction
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        endEntityProfileSession.addEndEntityProfile(admin, REDACTED_EEP, profile);
        redactedEepId = endEntityProfileSession.getEndEntityProfileId(REDACTED_EEP);
        
        profile = new EndEntityProfile();
        profile.removeField(DnComponents.COMMONNAME, 0);
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.ORGANIZATIONALUNIT);
        profile.addField(DnComponents.DNSNAME);
        profile.addField(DnComponents.RFC822NAME);
        profile.setAvailableCAs(Arrays.asList(SecConst.ALLCAS));
        endEntityProfileSession.addEndEntityProfile(admin, NON_REDACTED_EEP, profile);
        nonRedactedEepId = endEntityProfileSession.getEndEntityProfileId(NON_REDACTED_EEP);
        
    }
    
    @AfterClass
    public static void tearDownClass() throws Exception {
        for (final String username : usernames) {
            try {
                endEntityManagementSession.deleteUser(admin, username);
            } catch (Exception e) {
                // NOPMD, ignore errors so we don't stop deleting users because one of them does not exist.
            }
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, NON_REDACTED_EEP);
        } catch (Exception e) {
            // NOPMD, ignore errors
        }
        try {
            endEntityProfileSession.removeEndEntityProfile(admin, REDACTED_EEP);
        } catch (Exception e) {
            // NOPMD, ignore errors
        }
        
    }
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        
    }
    
    // MapToStringConverter from adminweb
    private String getAsString(final Map<String,Object> map) {
        final StringBuilder sb = new StringBuilder();
        if (map.size() == 1 && map.containsKey("msg")) {
            final String ret = (String) map.get("msg");
            if (ret != null) {
                return ret;
            }
        }
        for (final Object key : map.keySet()) {
            if (sb.length()!=0) {
                sb.append("; ");
            }
            sb.append(key).append('=').append(map.get(key));
        }
        return sb.toString();
    }
    
    @Test
    public void testRedactEndEntity() throws Exception {
        testRedactEndEntity(redactedEepId, true);
    }
    
    @Test
    public void testNonRedactEndEntity() throws Exception {
        testRedactEndEntity(nonRedactedEepId, false);
    }    
    
    private void testRedactEndEntity(int endEntityProfileId, boolean redact) throws Exception {
        
        long startTime = System.currentTimeMillis();
        Random rand = new Random();
        String userName = this.getClass().getName() + rand.nextLong();
        usernames.add(userName);
        String subjectDn = "OU=" + userName;
        String san = "dnsName=" + userName;
        EndEntityInformation endEntityInformation = new EndEntityInformation(userName,  
                subjectDn, caId, san, null, 
                EndEntityTypes.ENDUSER.toEndEntityType(), 
                endEntityProfileId, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        endEntityInformation.setPassword(userName);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        
        endEntityManagementSession.addUser(admin, endEntityInformation, false);
        log.info("created user: " + userName + "," + "OU=" + userName);

        assertAuditLogRedacted(startTime, subjectDn, san, redact);
        
        // update EE
        startTime = System.currentTimeMillis();
        san += ",rfc822Name=" + userName;
        endEntityInformation.setSubjectAltName(san);
        endEntityManagementSession.changeUser(admin, endEntityInformation, false);
        log.info("updated user: " + userName);

        if(redact) {
            assertAuditLogRedacted(startTime, subjectDn, san, redact);
        }
        
        // enroll EE and revoke certs 
        startTime = System.currentTimeMillis();
        enrollEeAndRevokeCerts(userName, subjectDn, san);
        assertAuditLogRedacted(startTime, subjectDn, san, redact);
        
        // rename EE
        startTime = System.currentTimeMillis();
        String newUserName = this.getClass().getName() + rand.nextLong();
        endEntityManagementSession.renameEndEntity(admin, userName, newUserName);
        log.info("renamed user: " + userName + ", renamed to:  " + newUserName);

        if(redact) {
            assertAuditLogRedacted(startTime, subjectDn, san, redact);
        }
        
        // delete EE
        startTime = System.currentTimeMillis();
        endEntityManagementSession.deleteUser(admin, newUserName);
        log.info("deleted user: " + userName + ", renamed to:  " + newUserName);

        if(redact) {
            assertAuditLogRedacted(startTime, subjectDn, san, redact);
        }
        
    }
    
    @Test
    public void testRedactEndEntityThrowAwayCert() throws Exception {
        // expected redaction always
        testRevokeThrowAwayCertAndPublishViaQueue(REDACTED_EEP, redactedEepId);
    }
    
    @Test
    public void testNonRedactEndEntityThrowAwayCert() throws Exception {
        // expected redaction always
        testRevokeThrowAwayCertAndPublishViaQueue(NON_REDACTED_EEP, nonRedactedEepId);
    }
    
    @Test
    public void testRedactEndEntityThrowAwayCertEnroll() throws Exception {
        testRevokeThrowAwayUserEnroll(REDACTED_EEP, redactedEepId, true);
    }
    
    @Test
    public void testNonRedactEndEntityThrowAwayCertEnroll() throws Exception {
        testRevokeThrowAwayUserEnroll(NON_REDACTED_EEP, nonRedactedEepId, false);
    }
    
    public void testRevokeThrowAwayUserEnroll(String profileName, int endEntityProfileId, boolean redact) throws Exception {
        Random rand = new Random();
        String userName = this.getClass().getName() + rand.nextLong();
        usernames.add(userName);
        String subjectDn = "OU=" + userName;
        String san = "dnsName=" + userName;
        BigInteger serialNumber = null;
        long startTime = 0L;
        try {
            final CAInfo cainfo = setUpThrowAwayPublishingTest(true, true); // use publisher queue. use no conflict table.            
            int certProfileId = certificateProfileSession.getCertificateProfileId(THROWAWAY_CERT_PROFILE);
            EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
            List<Integer> availableCertProfileIds = profile.getAvailableCertificateProfileIds();
            availableCertProfileIds.add(certProfileId);
            profile.setAvailableCertificateProfileIds(availableCertProfileIds);
            endEntityProfileSession.changeEndEntityProfile(admin, profileName, profile);
            
            startTime = System.currentTimeMillis();
            EndEntityInformation endEntityInformation = new EndEntityInformation(userName,  
                    subjectDn, cainfo.getCAId(), san, null, 
                    EndEntityTypes.ENDUSER.toEndEntityType(), 
                    endEntityProfileId, 
                    certProfileId, SecConst.TOKEN_SOFT_P12, null);
            endEntityInformation.setPassword(userName);
            endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
            
            endEntityManagementSession.addUser(admin, endEntityInformation, false);
            log.error("created user: " + userName + "," + "OU=" + userName);
            
            KeyPair keypair = KeyTools.genKeys("2048", "RSA");
            
            Certificate cert = signSession.createCertificate(admin, userName, userName, new PublicKeyWrapper(keypair.getPublic()));
            serialNumber = CertTools.getSerialNumber(cert);
            
        } finally {
            assertAuditLogRedacted(startTime, subjectDn, san, redact);
            cleanUpThrowAwayPublishingTest(serialNumber);
            final String fingerprint = noConflictCertificateStoreSession.generateDummyFingerprint("CN="+getTestCAName(), serialNumber);
            for (final PublisherQueueData entry : publisherQueueSession.getEntriesByFingerprint(fingerprint)) {
                log.debug("Removing publisher queue entry");
                publisherQueueSession.removeQueueData(entry.getPk());
            }
        }
    }
    
    public void testRevokeThrowAwayCertAndPublishViaQueue(String profileName, int endEntityProfileId) throws Exception {
        Random rand = new Random();
        String userName = this.getClass().getName() + rand.nextLong();
        usernames.add(userName);
        String subjectDn = "OU=" + userName;
        String san = "dnsName=" + userName;
        BigInteger serialNumber = null;
        long startTime = 0L;
        try {
            final CAInfo cainfo = setUpThrowAwayPublishingTest(true, true); // use publisher queue. use no conflict table.            
            serialNumber = new BigInteger("123456788A43197F", 16);
            
            startTime = System.currentTimeMillis();
            final BasePublisher publisher = publisherSession.getPublisher(THROWAWAY_PUBLISHER);
            // Place on hold
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            endEntityManagementSession.revokeCert(admin, serialNumber, cainfo.getSubjectDN(), RevocationReasons.CERTIFICATEHOLD.getDatabaseValue());
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
            assertEquals("Publisher should have been called with 'on hold' revocation reason.",
                    RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Activate again
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, serialNumber, cainfo.getSubjectDN(), RevocationReasons.NOT_REVOKED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
            assertEquals("Publisher should have been called THROW_AWAY_CERT_SERIAL 'not revoked' revocation reason.",
                    RevocationReasons.NOT_REVOKED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
            // Revoke permanently
            publisherTestSession.setLastMockedThrowAwayRevocationReason(-123);
            assertEquals("Publisher should not have been called.", -123, publisherTestSession.getLastMockedThrowAwayRevocationReason());
            endEntityManagementSession.revokeCert(admin, serialNumber, cainfo.getSubjectDN(), RevocationReasons.SUPERSEDED.getDatabaseValue());
            publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(admin, publisher, PublishQueueProcessWorker.DEFAULT_QUEUE_WORKER_JOBS);
            assertEquals("Publisher should have been called with 'superseeded' revocation reason.",
                    RevocationReasons.SUPERSEDED.getDatabaseValue(), publisherTestSession.getLastMockedThrowAwayRevocationReason());
        } finally {
            assertAuditLogRedacted(startTime, subjectDn, san, true); // always redaction expected
            cleanUpThrowAwayPublishingTest(serialNumber);
            final String fingerprint = noConflictCertificateStoreSession.generateDummyFingerprint("CN="+getTestCAName(), serialNumber);
            for (final PublisherQueueData entry : publisherQueueSession.getEntriesByFingerprint(fingerprint)) {
                log.debug("Removing publisher queue entry");
                publisherQueueSession.removeQueueData(entry.getPk());
            }
        }
    }
    
    
    private void enrollEeAndRevokeCerts(String userName, String subjectDn, String san) throws Exception {
        KeyPair keypair = KeyTools.genKeys("2048", "RSA");
        
        try {
            signSession.createCertificate(admin, userName, "badPassword", new PublicKeyWrapper(keypair.getPublic()));
            fail("authed with bad password");
        } catch (Exception e) {
        }
        
        Certificate cert = signSession.createCertificate(admin, userName, userName, new PublicKeyWrapper(keypair.getPublic()));
        CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        // Revoke the certificate, put on hold
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), RevokedCertInfo.NOT_REVOKED);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, status.revocationReason);

        // Unrevoke the certificate, but with different code
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);

        // Revoke again certificate permanently
        endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert),
                RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
        status = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
        assertEquals(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, status.revocationReason);

    }
    
    private void assertAuditLogRedacted(long startTime, String subjectDn, String san, boolean redact) throws Exception {
        List<? extends AuditLogEntry> auditLogsGenerated = 
                ejbcaAuditorSession.selectAuditLog(admin, DEVICE_NAME, 0, 1000, "a.timeStamp > " + startTime, null, null);
        
        boolean foundSubjectDn = false; 
        boolean foundSan = false; 
        String matchString = null;
        for(AuditLogEntry x: auditLogsGenerated) {
            String auditLogEntry = getAsString(x.getMapAdditionalDetails());
            foundSubjectDn |= auditLogEntry.contains(subjectDn);
            if(redact & foundSubjectDn) {
                matchString = auditLogEntry;
                break;
            }
            foundSan |= auditLogEntry.contains(san);
            if(redact & foundSan) {
                matchString = auditLogEntry;
                break;
            }
        }
        assertEquals("subject dn redaction is opposite. redaction expected: " + redact + " : " + matchString, foundSubjectDn, !redact);
        assertEquals("SAN redaction is opposite. redaction expected: " + redact + " : " + matchString, foundSan, !redact);
    }
    
    protected CAInfo setUpThrowAwayPublishingTest(final boolean useQueue, final boolean useNoConflictCertificateData) throws Exception {
        return super.setUpThrowAwayPublishingTest(useQueue, useNoConflictCertificateData, true, caId, THROWAWAY_CERT_PROFILE, THROWAWAY_PUBLISHER);
    }
    
    protected void cleanUpThrowAwayPublishingTest(BigInteger serialNumber) throws Exception {
        super.cleanUpThrowAwayPublishingTest(caId, THROWAWAY_CERT_PROFILE, THROWAWAY_PUBLISHER, serialNumber);
    }

}
