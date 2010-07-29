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

package org.ejbca.core.model.approval.approvalrequests;

import java.io.File;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import javax.ejb.DuplicateKeyException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

/**
 * Tests approvals which are required by the certificate profile and not only by
 * the CA or instead of by the CA.
 * 
 * @author Markus Kilås
 * @version $Id: ApprovalEnforcedByCertificateProfileTest.java 9435 2010-07-14
 *          15:18:39Z mikekushner $
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

    private static final Admin admin1 = new Admin(Admin.TYPE_RA_USER);

    private static String adminUsername;

    private static Collection<String> createdUsers = new LinkedList<String>();

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private KeyRecoverySessionRemote keyRecoverySession = InterfaceCache.getKeyRecoverySession();
    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoProviderTools.installBCProvider();
    }

    public void test00SetupDatabase() throws Exception {
        log.info("test00SetupDatabase");
        createTestCA();

        // Create admin end entity
        adminUsername = genRandomUserName("approvalEnforcedTestAdmin");
        createUser(admin1, adminUsername, caid, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER);

        // Create new CA
        approvalCAID = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_ApprovalCA", new Integer[] {}, caAdminSession,
                SecConst.CERTPROFILE_FIXED_ROOTCA);

        // Create certificate profiles
        certProfileIdNoApprovals = createCertificateProfile(admin1, CERTPROFILE1, new Integer[] {}, CertificateProfile.TYPE_ENDENTITY);
        certProfileIdEndEntityApprovals = createCertificateProfile(admin1, CERTPROFILE2, new Integer[] { CAInfo.REQ_APPROVAL_ADDEDITENDENTITY },
                CertificateProfile.TYPE_ENDENTITY);
        certProfileIdActivateCATokensApprovals = createCertificateProfile(admin1, CERTPROFILE3, new Integer[] { CAInfo.REQ_APPROVAL_ACTIVATECATOKEN },
                CertificateProfile.TYPE_ROOTCA);
        certProfileIdKeyRecoveryApprovals = createCertificateProfile(admin1, CERTPROFILE4, new Integer[] { CAInfo.REQ_APPROVAL_KEYRECOVER },
                CertificateProfile.TYPE_ENDENTITY);
        certProfileIdAllApprovals = createCertificateProfile(admin1, CERTPROFILE5, new Integer[] { CAInfo.REQ_APPROVAL_ACTIVATECATOKEN,
                CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, CAInfo.REQ_APPROVAL_KEYRECOVER, CAInfo.REQ_APPROVAL_REVOCATION }, CertificateProfile.TYPE_ENDENTITY);
        // Other CAs
        anotherCAID1 = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_AnotherCA1", new Integer[] {}, caAdminSession,
                SecConst.CERTPROFILE_FIXED_ROOTCA);
        anotherCAID2 = createCA(admin1, ApprovalEnforcedByCertificateProfileTest.class.getSimpleName() + "_AnotherCA2", new Integer[] {}, caAdminSession,
                certProfileIdActivateCATokensApprovals);

        // Create an end entity profile with the certificate profiles
        endEntityProfileId = createEndEntityProfile(admin1, ENDENTITYPROFILE, new int[] { certProfileIdNoApprovals, certProfileIdEndEntityApprovals,
                certProfileIdActivateCATokensApprovals, certProfileIdKeyRecoveryApprovals, certProfileIdAllApprovals });

        log.info("approvalCAID=" + approvalCAID);
        log.info("certProfileId1=" + certProfileIdNoApprovals);
        log.info("certProfileId2=" + certProfileIdEndEntityApprovals);
        log.info("endEntityProfileId=" + endEntityProfileId);
    }

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
        } catch (WaitingForApprovalException ex) {
            // OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }

        // Create user with cert profile that requires all approvals
        try {
            String username3 = genRandomUserName("test01_3");
            createUser(admin1, username3, approvalCAID, endEntityProfileId, certProfileIdAllApprovals);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) {
            // OK
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

    public void test02ActivateCAToken() throws Exception {
        log.info("test02ActivateCAToken");

        try {
            caAdminSession.deactivateCAToken(admin1, anotherCAID1);
            caAdminSession.activateCAToken(admin1, anotherCAID1, "foo123", raAdminSession.loadGlobalConfiguration(admin1));
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        }

        try {
            caAdminSession.deactivateCAToken(admin1, anotherCAID2);
            caAdminSession.activateCAToken(admin1, anotherCAID2, "foo123", raAdminSession.loadGlobalConfiguration(admin1));
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) {
            // OK
        } catch (ApprovalException ex) {
            // OK
        }
    }

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
        } catch (WaitingForApprovalException ex) {
            // OK
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            fail();
        }
    }

    public void test04KeyRecovery() throws Exception {
        log.info("test04KeyRecovery");

        assertTrue(certProfileIdNoApprovals != 0);
        assertTrue(certProfileIdKeyRecoveryApprovals != 0);

        // Create user with a profile that does NOT require approvals for key
        // recovery
        try {
            String username1 = genRandomUserName("test04_1");
            String email = "test@example.com";
            KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            userAdminSession.addUser(admin1, username1, "foo123", "CN=TESTKEYREC1" + username1, /*
                                                                                                 * "rfc822name="
                                                                                                 * +
                                                                                                 * email
                                                                                                 */null, email, false, endEntityProfileId,
                    certProfileIdNoApprovals, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, approvalCAID);
            X509Certificate cert = (X509Certificate) signSession.createCertificate(admin1, username1, "foo123", keypair.getPublic());

            keyRecoverySession.addKeyRecoveryData(admin1, cert, username1, keypair);

            assertTrue("Couldn't mark user for recovery in database", !keyRecoverySession.isUserMarked(admin1, username1));
            userAdminSession.prepareForKeyRecovery(admin1, username1, endEntityProfileId, cert);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(admin1, username1));
            KeyRecoveryData data = keyRecoverySession.keyRecovery(admin1, username1, SecConst.EMPTY_ENDENTITYPROFILE);
            assertTrue("Couldn't recover keys from database", Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));
        } catch (WaitingForApprovalException ex) {
            fail("This profile should not require approvals");
        }

        // Create user with a profile that does require approvals for key
        // recovery
        try {
            String username1 = genRandomUserName("test04_2");
            String email = "test@example.com";
            KeyPair keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            userAdminSession.addUser(admin1, username1, "foo123", "CN=TESTKEYREC2" + username1, /*
                                                                                                 * "rfc822name="
                                                                                                 * +
                                                                                                 * email
                                                                                                 */null, email, false, endEntityProfileId,
                    certProfileIdKeyRecoveryApprovals, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, approvalCAID);
            X509Certificate cert = (X509Certificate) signSession.createCertificate(admin1, username1, "foo123", keypair.getPublic());
            keyRecoverySession.addKeyRecoveryData(admin1, cert, username1, keypair);

            assertTrue("Couldn't mark user for recovery in database", !keyRecoverySession.isUserMarked(admin1, username1));
            userAdminSession.prepareForKeyRecovery(admin1, username1, endEntityProfileId, cert);
            fail("This should have caused an approval request");
        } catch (WaitingForApprovalException ex) {
            // OK
        }
    }

    public void test99RemoveCreated() {
        log.info("test99RemoveCreated");

        // Remove users
        for (Object o : createdUsers) {
            try {
                userAdminSession.deleteUser(admin1, (String) o);
            } catch (Exception ex) {
                log.error("Remove user", ex);
            }
        }

        // Remove CAs
        removeCA(anotherCAID1);
        removeCA(anotherCAID2);
        removeCA(approvalCAID);

        // Remove end entity profile
    
            raAdminSession.removeEndEntityProfile(admin1, ENDENTITYPROFILE);
        

        // Remove certificate profiles
        removeCertificateProfile(CERTPROFILE1);
        removeCertificateProfile(CERTPROFILE2);
        removeCertificateProfile(CERTPROFILE3);
        removeCertificateProfile(CERTPROFILE4);
        removeCertificateProfile(CERTPROFILE5);
    }

    private void removeCA(int caId) {
        try {
            caAdminSession.removeCA(admin1, caId);
        } catch (AuthorizationDeniedException e) {
            log.error("Remove CA", e);
        }
    }

    private void removeCertificateProfile(String certProfileName) {

        certificateStoreSession.removeCertificateProfile(admin1, certProfileName);
    }

    private String genRandomUserName(String usernameBase) {
        return usernameBase + (new Integer((new Random(new Date().getTime() + 4711)).nextInt(999999))).toString();
    }

    private int createCertificateProfile(Admin admin, String certProfileName, Integer[] reqApprovals, int type) throws Exception {
        certificateStoreSession.removeCertificateProfile(admin, certProfileName);

        CertificateProfile certProfile = new CertificateProfile();
        certProfile.setType(type);
        certProfile.setApprovalSettings(Arrays.asList(reqApprovals));

        certificateStoreSession.addCertificateProfile(admin, certProfileName, certProfile);
        int certProfileId = certificateStoreSession.getCertificateProfileId(admin1, certProfileName);
        assertTrue(certProfileId != 0);

        CertificateProfile profile2 = certificateStoreSession.getCertificateProfile(admin, certProfileId);
        assertNotNull(profile2.getApprovalSettings());
        assertEquals(reqApprovals.length, profile2.getApprovalSettings().size());

        return certProfileId;
    }

    public static int createCA(Admin internalAdmin, String nameOfCA, Integer[] approvalRequirementTypes, CAAdminSessionRemote caAdminSession, int certProfileId)
            throws Exception {
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setSignKeySpec("1024");
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setEncKeySpec("1024");
        List<Integer> approvalSettings = Arrays.asList(approvalRequirementTypes);
        log.info("approvalSettings: " + approvalSettings);

        X509CAInfo cainfo = new X509CAInfo("CN=" + nameOfCA, nameOfCA, SecConst.CA_ACTIVE, new Date(), "", certProfileId, 365, new Date(System
                .currentTimeMillis()
                + 364 * 24 * 3600 * 1000), CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, null, catokeninfo, "Used for testing approvals", -1, null, null, 24, 0, 10,
                0, new ArrayList(), true, false, true, false, "", "", "", "", true, new ArrayList(), false, approvalSettings, 1, false, true, false, false,
                true, true, true, false, true);
        int caID = cainfo.getCAId();
        try {
            caAdminSession.revokeCA(internalAdmin, caID, RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            caAdminSession.removeCA(internalAdmin, caID);
        } catch (Exception e) {
        }
        caAdminSession.createCA(internalAdmin, cainfo);
        cainfo = (X509CAInfo) caAdminSession.getCAInfo(internalAdmin, caID);
        assertNotNull(cainfo);

        log.info("cainfo has " + cainfo.getApprovalSettings() + "  and with  " + cainfo.getNumOfReqApprovals());

        return caID;
    }

    private void createUser(Admin admin, String username, int caID, int endEntityProfileId, int certProfileId) throws DuplicateKeyException, RemoteException,
            AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {
        log.info("createUser: username=" + username + ", certProfileId=" + certProfileId);
        UserDataVO userdata = new UserDataVO(username, "CN=" + username, caID, null, null, 1, endEntityProfileId, certProfileId, SecConst.TOKEN_SOFT_P12, 0,
                null);
        userdata.setPassword("foo123");
        // userdata.setKeyRecoverable(true);
        createUser(admin, userdata);
    }

    private void createUser(Admin admin, UserDataVO userdata) throws DuplicateKeyException, RemoteException, AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {
        userAdminSession.addUser(admin, userdata, true);
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        UserDataVO userdata2 = userAdminSession.findUser(admin, userdata.getUsername());
        assertNotNull("findUser: " + userdata.getUsername(), userdata2);
        createdUsers.add(userdata.getUsername());
        log.info("created: " + userdata.getUsername());
    }

    private void changeUserDN(Admin admin, String username, String newDN) throws DuplicateKeyException, RemoteException, AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {

        UserDataVO userdata = userAdminSession.findUser(admin, username);
        assertNotNull(userdata);
        userdata.setDN(newDN);
        userAdminSession.changeUser(admin, userdata, true);
    }

    private void changeUserCertProfile(Admin admin, String username, int newCertProfileId) throws DuplicateKeyException, RemoteException,
            AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {

        UserDataVO userdata = userAdminSession.findUser(admin, username);
        assertNotNull("findUser: " + username, userdata);
        userdata.setCertificateProfileId(newCertProfileId);
        userAdminSession.changeUser(admin, userdata, true);
    }

    private int createEndEntityProfile(Admin admin, String endEntityProfileName, int[] certProfiles) throws RemoteException, EndEntityProfileExistsException {
        EndEntityProfile profile;

        raAdminSession.removeEndEntityProfile(admin, endEntityProfileName);

        StringBuilder availableCertProfiles = new StringBuilder();
        for (int id : certProfiles) {
            availableCertProfiles.append(id);
            availableCertProfiles.append(EndEntityProfile.SPLITCHAR);
        }

        profile = new EndEntityProfile();
        profile.setUse(EndEntityProfile.ENDTIME, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, new Integer(approvalCAID).toString());
        profile.setUse(EndEntityProfile.STARTTIME, 0, true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles.toString());
        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, new Integer(certProfiles[0]).toString());
        profile.setValue(EndEntityProfile.DEFAULTCA, 0, new Integer(approvalCAID).toString());
        raAdminSession.addEndEntityProfile(admin, endEntityProfileName, profile);

        int endEntityProfileId = raAdminSession.getEndEntityProfileId(admin1, endEntityProfileName);
        assertTrue(endEntityProfileId != 0);

        return endEntityProfileId;
    }

}
