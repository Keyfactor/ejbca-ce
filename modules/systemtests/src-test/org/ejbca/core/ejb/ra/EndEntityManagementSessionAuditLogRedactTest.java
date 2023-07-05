package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.audit.EjbcaAuditorTestSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
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
        
    }
    
    
    private void enrollEeAndRevokeCerts(String userName, String subjectDn, String san) throws Exception {
        KeyPair keypair = KeyTools.genKeys("2048", "RSA");
        
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
        for(AuditLogEntry x: auditLogsGenerated) {
            foundSubjectDn |= getAsString(x.getMapAdditionalDetails()).contains(subjectDn);
            foundSan |= getAsString(x.getMapAdditionalDetails()).contains(san);
        }
        assertEquals("subject dn redaction is opposite. redaction expected: " + redact, foundSubjectDn, !redact);
        assertEquals("SAN redaction is opposite. redaction expected: " + redact, foundSan, !redact);
    }

}
