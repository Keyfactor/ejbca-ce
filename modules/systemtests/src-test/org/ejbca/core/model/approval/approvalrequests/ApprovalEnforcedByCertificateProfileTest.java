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

package org.ejbca.core.model.approval.approvalrequests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests approvals which are required by the certificate profile and not only by the CA or instead of by the CA.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ApprovalEnforcedByCertificateProfileTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(ApprovalEnforcedByCertificateProfileTest.class);

    private static final String ENDENTITYPROFILE = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "EndEntityProfile";

    private static final String CERTPROFILE1 = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "CertProfile1";
    private static final String CERTPROFILE2 = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "CertProfile2";
    private static final String CERTPROFILE3 = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "CertProfile3";
    private static final String CERTPROFILE4 = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "CertProfile4";
    private static final String CERTPROFILE5 = ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "CertProfile5";

    private static int endEntityProfileId;

    private static int certProfileIdNoApprovals;
    private static int certProfileIdEndEntityApprovals;
    private static int certProfileIdKeyRecoveryApprovals;
    private static int certProfileIdActivateCATokensApprovals;
    private static int certProfileIdAllApprovals;

    private int caid = getTestCAId();
    private static int approvalCAID;
    private static int anotherCAID1;
    private static int anotherCAID2;

    private static final AuthenticationToken admin1 = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalEnforcedByCertificateProfileTest"));

    private static String adminUsername;
    
    private final String cliUserName = EjbcaConfiguration.getCliDefaultUser();
    private final String cliPassword = EjbcaConfiguration.getCliDefaultPassword();
    private int cryptoTokenId1 = 0;
    private int cryptoTokenId2 = 0;
    private int cryptoTokenId3 = 0;
    
    private static Collection<String> createdUsers = new LinkedList<String>();

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        log.info("test00SetupDatabase");

        // Create admin end entity
        adminUsername = genRandomUserName("approvalEnforcedTestAdmin");
        createUser(admin1, adminUsername, caid, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);

        // Create new CA
        cryptoTokenId1 = CryptoTokenTestUtils.createCryptoTokenForCA(admin1, "ca1", "1024");
        final CAToken catoken1 = CaTestUtils.createCaToken(cryptoTokenId1, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        cryptoTokenId2 = CryptoTokenTestUtils.createCryptoTokenForCA(admin1, "ca2", "1024");
        final CAToken catoken2 = CaTestUtils.createCaToken(cryptoTokenId2, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        cryptoTokenId3 = CryptoTokenTestUtils.createCryptoTokenForCA(admin1, "ca3", "1024");
        final CAToken catoken3 = CaTestUtils.createCaToken(cryptoTokenId3, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

        approvalCAID = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_ApprovalCA", new Integer[] {},
                caAdminSession, caSession, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, catoken1);

        // Create certificate profiles
        certProfileIdNoApprovals = createCertificateProfile(admin1, CERTPROFILE1, new Integer[] {}, CertificateConstants.CERTTYPE_ENDENTITY);
        certProfileIdEndEntityApprovals = createCertificateProfile(admin1, CERTPROFILE2, new Integer[] { CAInfo.REQ_APPROVAL_ADDEDITENDENTITY },
                CertificateConstants.CERTTYPE_ENDENTITY);
        certProfileIdActivateCATokensApprovals = createCertificateProfile(admin1, CERTPROFILE3,
                new Integer[] { CAInfo.REQ_APPROVAL_ACTIVATECA }, CertificateConstants.CERTTYPE_ROOTCA);
        certProfileIdKeyRecoveryApprovals = createCertificateProfile(admin1, CERTPROFILE4, new Integer[] { CAInfo.REQ_APPROVAL_KEYRECOVER },
                CertificateConstants.CERTTYPE_ENDENTITY);
        certProfileIdAllApprovals = createCertificateProfile(admin1, CERTPROFILE5, new Integer[] { CAInfo.REQ_APPROVAL_ACTIVATECA,
                CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, CAInfo.REQ_APPROVAL_KEYRECOVER, CAInfo.REQ_APPROVAL_REVOCATION },
                CertificateConstants.CERTTYPE_ENDENTITY);
        // Other CAs
        anotherCAID1 = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_AnotherCA1", new Integer[] {},
                caAdminSession, caSession, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, catoken2);
        anotherCAID2 = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_AnotherCA2", new Integer[] {},
                caAdminSession, caSession, certProfileIdActivateCATokensApprovals, catoken3);

        // Create an end entity profile with the certificate profiles
        endEntityProfileId = createEndEntityProfile(admin1, ENDENTITYPROFILE, new int[] { certProfileIdNoApprovals, certProfileIdEndEntityApprovals,
                certProfileIdActivateCATokensApprovals, certProfileIdKeyRecoveryApprovals, certProfileIdAllApprovals });

        log.info("approvalCAID=" + approvalCAID);
        log.info("certProfileId1=" + certProfileIdNoApprovals);
        log.info("certProfileId2=" + certProfileIdEndEntityApprovals);
        log.info("endEntityProfileId=" + endEntityProfileId);
    }

    @Test
    public void test01AddEditEndEntity() {
        log.info("test01AddEditEndEntity");

        assertTrue(certProfileIdNoApprovals != 0);
        assertTrue(certProfileIdEndEntityApprovals != 0);
        assertTrue(certProfileIdAllApprovals != 0);

        // Create user without requiring approval
        String username1 = genRandomUserName("test01_1");
        try {
            createUser(admin1, username1, approvalCAID, endEntityProfileId, certProfileIdNoApprovals);
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Create user with cert profile that requires approval
        try {
            String username2 = genRandomUserName("test01_2");
            createUser(admin1, username2, approvalCAID, endEntityProfileId, certProfileIdEndEntityApprovals);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) { // NOPMD: OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Create user with cert profile that requires all approvals
        try {
            String username3 = genRandomUserName("test01_3");
            createUser(admin1, username3, approvalCAID, endEntityProfileId, certProfileIdAllApprovals);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) { // NOPMD: OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Edit user without requiring approval
        try {
            changeUserDN(admin1, username1, "CN=test01_1_new");
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Edit user without requiring approval and change its profile to one
        // that requires approval
        // The new cert profile will cause a approval request
        try {
            changeUserCertProfile(admin1, username1, certProfileIdEndEntityApprovals);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) {
            // OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }
    }

    @Test
    public void test02ActivateCAToken() throws Exception {
        log.info("test02ActivateCAToken");
        try {
            caAdminSession.deactivateCAService(admin1, anotherCAID1);
            CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, anotherCAID1);
            assertEquals("CA should be offline", CAConstants.CA_OFFLINE, cainfo.getStatus());
            caAdminSession.activateCAService(admin1, anotherCAID1);
            cainfo = caSession.getCAInfo(roleMgmgToken, anotherCAID1);
            assertEquals("CA should be online", CAConstants.CA_ACTIVE, cainfo.getStatus());
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        }
        try {
            caAdminSession.deactivateCAService(admin1, anotherCAID2);
            CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, anotherCAID2);
            assertEquals("CA should be offline", CAConstants.CA_OFFLINE, cainfo.getStatus());
            caAdminSession.activateCAService(admin1, anotherCAID2);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) { // NOPMD: OK
        } catch (ApprovalException ex) {
            // OK
        }
    }

    @Test
    public void test03RevokeUser() throws Exception {
        log.info("test03RevokeUser");

        assertTrue(certProfileIdNoApprovals != 0);
        assertTrue(certProfileIdEndEntityApprovals != 0);

        // Create user with a profile that does NOT require approvals for
        // revoking users
        try {
            String username1 = genRandomUserName("test03_1");
            createUser(admin1, username1, approvalCAID, endEntityProfileId, certProfileIdNoApprovals);
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Create user with a profile that does require approvals for revoking
        // users
        try {
            String username2 = genRandomUserName("test03_2");
            createUser(admin1, username2, approvalCAID, endEntityProfileId, certProfileIdEndEntityApprovals);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) { // NOPMD: OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }
    }

    @Test
    public void test04KeyRecovery() throws Exception {
        log.info("test04KeyRecovery");

        assertTrue(certProfileIdNoApprovals != 0);
        assertTrue(certProfileIdKeyRecoveryApprovals != 0);

        // Create user with a profile that does NOT require approvals for key
        // recovery
        String username1 = genRandomUserName("test04_1");
        try {           
            String email = "test@example.com";
            KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            endEntityManagementSession.addUser(admin1, username1, "foo123", "CN=TESTKEYREC1" + username1, 
            		null, email, false, endEntityProfileId,
                    certProfileIdNoApprovals, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, approvalCAID);
            X509Certificate cert = (X509Certificate) signSession.createCertificate(admin1, username1, "foo123", keypair.getPublic());
            assertNotNull("Cert should have been created.", cert);
            keyRecoverySession.addKeyRecoveryData(admin1, cert, username1, keypair);
            assertTrue("Couldn't mark user for recovery in database", !keyRecoverySession.isUserMarked(username1));
            endEntityManagementSession.prepareForKeyRecovery(admin1, username1, endEntityProfileId, cert);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(username1));
            KeyRecoveryInformation data = keyRecoverySession.recoverKeys(admin1, username1, SecConst.EMPTY_ENDENTITYPROFILE);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        } finally {
            endEntityManagementSession.deleteUser(admin1, username1);
        }

        // Create user with a profile that does require approvals for key
        // recovery
        String username2 = genRandomUserName("test04_2");
        try {
            String email = "test@example.com";
            KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            endEntityManagementSession.addUser(admin1, username2, "foo123", "CN=TESTKEYREC2" + username2, null, email, false, endEntityProfileId,
                    certProfileIdKeyRecoveryApprovals, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, approvalCAID);
            X509Certificate cert = (X509Certificate) signSession.createCertificate(admin1, username2, "foo123", keypair.getPublic());
            keyRecoverySession.addKeyRecoveryData(admin1, cert, username2, keypair);

            assertTrue("Couldn't mark user for recovery in database", !keyRecoverySession.isUserMarked(username2));
            endEntityManagementSession.prepareForKeyRecovery(admin1, username2, endEntityProfileId, cert);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) {
            // OK
        } finally {
            endEntityManagementSession.deleteUser(admin1, username2);
        }
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

        // Remove users
        for (Object o : createdUsers) {
            try {
                endEntityManagementSession.deleteUser(admin1, (String) o);
            } catch (Exception ex) {
                log.error("Remove user", ex);
            }
        }

        // Remove CAs
        removeCA(anotherCAID1);
        removeCA(anotherCAID2);
        removeCA(approvalCAID);

        // Remove end entity profile

        endEntityProfileSession.removeEndEntityProfile(admin1, ENDENTITYPROFILE);

        // Remove certificate profiles
        removeCertificateProfile(CERTPROFILE1);
        removeCertificateProfile(CERTPROFILE2);
        removeCertificateProfile(CERTPROFILE3);
        removeCertificateProfile(CERTPROFILE4);
        removeCertificateProfile(CERTPROFILE5);
        // Remove the CA's CryptoTokens
        CryptoTokenTestUtils.removeCryptoToken(admin1, cryptoTokenId1);
        CryptoTokenTestUtils.removeCryptoToken(admin1, cryptoTokenId2);
        CryptoTokenTestUtils.removeCryptoToken(admin1, cryptoTokenId3);
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    private void removeCA(int caId) {
        try {
            caSession.removeCA(admin1, caId);
        } catch (AuthorizationDeniedException e) {
            log.error("Remove CA", e);
        }
    }

    private void removeCertificateProfile(String certProfileName) throws AuthorizationDeniedException {
        certificateProfileSession.removeCertificateProfile(admin1, certProfileName);
    }

    private String genRandomUserName(String usernameBase) {
        return usernameBase + (Integer.valueOf((new Random(new Date().getTime() + 4711)).nextInt(999999))).toString();
    }

    private int createCertificateProfile(AuthenticationToken admin, String certProfileName, Integer[] reqApprovals, int type) throws Exception {
        certificateProfileSession.removeCertificateProfile(admin, certProfileName);

        CertificateProfile certProfile = new CertificateProfile();
        certProfile.setType(type);
        certProfile.setApprovalSettings(Arrays.asList(reqApprovals));

        certificateProfileSession.addCertificateProfile(admin, certProfileName, certProfile);
        int certProfileId = certificateProfileSession.getCertificateProfileId(certProfileName);
        assertTrue(certProfileId != 0);

        CertificateProfile profile2 = certificateProfileSession.getCertificateProfile(certProfileId);
        assertNotNull(profile2.getApprovalSettings());
        assertEquals(reqApprovals.length, profile2.getApprovalSettings().size());

        return certProfileId;
    }

    public static int createCA(AuthenticationToken internalAdmin, String nameOfCA, Integer[] approvalRequirementTypes,
            CAAdminSessionRemote caAdminSession, CaSessionRemote caSession, int certProfileId, CAToken catoken) throws Exception {
        final List<Integer> approvalSettings = approvalRequirementTypes.length == 0 ? new ArrayList<Integer>() : Arrays.asList(approvalRequirementTypes);
        log.info("approvalSettings: " + approvalSettings);

        ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        X509CAInfo cainfo = new X509CAInfo("CN=" + nameOfCA, nameOfCA, CAConstants.CA_ACTIVE, certProfileId, 365, CAInfo.SELFSIGNED, null, catoken);
        cainfo.setExpireTime(new Date(System.currentTimeMillis() + 364 * 24 * 3600 * 1000));
        cainfo.setDescription("Used for testing approvals");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        cainfo.setApprovalSettings(approvalSettings);
        int caID = cainfo.getCAId();
        try {
            caAdminSession.revokeCA(internalAdmin, caID, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            caSession.removeCA(internalAdmin, caID);
        } catch (Exception e) {
        }
        caAdminSession.createCA(internalAdmin, cainfo);
        cainfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, caID);
        assertNotNull(cainfo);

        log.info("cainfo has " + cainfo.getApprovalSettings() + "  and with  " + cainfo.getNumOfReqApprovals());

        return caID;
    }

    private void createUser(AuthenticationToken admin, String username, int caID, int endEntityProfileId, int certProfileId)
            throws EndEntityExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ApprovalException,
            WaitingForApprovalException, Exception {
        log.info("createUser: username=" + username + ", certProfileId=" + certProfileId);
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certProfileId,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        // userdata.setKeyRecoverable(true);
        createUser(cliUserName, cliPassword, userdata);
    }

    private void createUser(String cliUserName, String cliPassword, EndEntityInformation userdata) throws EndEntityExistsException, AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {
        endEntityManagementSession.addUser(admin1, userdata, true);
        File tmpfile = File.createTempFile("ejbca", "p12");
        BatchCreateTool.createAllNew(admin1, tmpfile.getParent());
        EndEntityInformation userdata2 = endEntityAccessSession.findUser(admin1, userdata.getUsername());
        assertNotNull("findUser: " + userdata.getUsername(), userdata2);
        createdUsers.add(userdata.getUsername());
        log.info("created: " + userdata.getUsername());
    }

    private void changeUserDN(AuthenticationToken admin, String username, String newDN) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {

        EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
        assertNotNull(userdata);
        userdata.setDN(newDN);
        log.debug("changeUser: username=" + username + ", DN=" + userdata.getDN() + ", password=" + userdata.getPassword() + ", certProfileId="
                + userdata.getCertificateProfileId());
        endEntityManagementSession.changeUser(admin, userdata, true);
    }

    private void changeUserCertProfile(AuthenticationToken admin, String username, int newCertProfileId) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {
        EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
        assertNotNull("findUser: " + username, userdata);
        userdata.setCertificateProfileId(newCertProfileId);
        endEntityManagementSession.changeUser(admin, userdata, true);
    }

    private int createEndEntityProfile(AuthenticationToken admin, String endEntityProfileName, int[] certProfiles)
            throws EndEntityProfileExistsException, AuthorizationDeniedException, EndEntityProfileNotFoundException {
        EndEntityProfile profile;
        endEntityProfileSession.removeEndEntityProfile(admin, endEntityProfileName);

        StringBuilder availableCertProfiles = new StringBuilder();
        for (int id : certProfiles) {
            availableCertProfiles.append(id);
            availableCertProfiles.append(EndEntityProfile.SPLITCHAR);
        }

        profile = new EndEntityProfile();
        profile.setUse(EndEntityProfile.ENDTIME, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, String.valueOf(approvalCAID));
        profile.setUse(EndEntityProfile.STARTTIME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles.toString());
        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, String.valueOf(certProfiles[0]));
        profile.setValue(EndEntityProfile.DEFAULTCA, 0, String.valueOf(approvalCAID));
        endEntityProfileSession.addEndEntityProfile(admin, endEntityProfileName, profile);

        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
        assertTrue(endEntityProfileId != 0);

        return endEntityProfileId;
    }

}
