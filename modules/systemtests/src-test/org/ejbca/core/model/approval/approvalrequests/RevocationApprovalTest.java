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
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RevocationApprovalTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(RevocationApprovalTest.class);
    
    private static final String P12_FOLDER_NAME = "p12";

    
    private static String requestingAdminUsername = null;
    private static String adminUsername = null;

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "RevocationApprovalTest"));
    private static AuthenticationToken requestingAdmin = null;
    private static AuthenticationToken approvingAdmin = null;
    private static ArrayList<AccessUserAspectData> adminentities;

    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
            SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private int caid = getTestCAId();
    private int approvalCAID;
    private int cryptoTokenId = 0;
    private int approvalProfileId = -1;
    
    private List<File> fileHandles = new ArrayList<File>();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // An if on a static thing here, just so we don't have to batch generate new certs for every test
        if (adminUsername == null) {
            adminUsername = "RevocationApprovalTest_revocationTestAdmin";
            requestingAdminUsername = "RevocationApprovalTest_revocationTestRequestingAdmin";
            EndEntityInformation userdata = new EndEntityInformation(adminUsername, "CN=" + adminUsername, caid, null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            endEntityManagementSession.addUser(internalAdmin, userdata, true);
            EndEntityInformation userdata2 = new EndEntityInformation(requestingAdminUsername, "CN=" + requestingAdminUsername, caid, null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata2.setPassword("foo123");
            endEntityManagementSession.addUser(internalAdmin, userdata2, true);
            fileHandles.addAll(BatchCreateTool.createAllNew(internalAdmin, new File(P12_FOLDER_NAME)));
        }
        RoleData role = roleAccessSession.findRole(getRoleName());
        if (role == null) {
            role = roleManagementSession.create(internalAdmin, getRoleName());
        }
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(getRoleName(), AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(getRoleName(), AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);
        adminentities = new ArrayList<AccessUserAspectData>();
        adminentities.add(new AccessUserAspectData(getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminUsername));
        adminentities.add(new AccessUserAspectData(getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, requestingAdminUsername));
        roleManagementSession.addSubjectsToRole(internalAdmin, role, adminentities);
        accessControlSession.forceCacheExpire();

        X509Certificate admincert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminUsername)).iterator().next();
        X509Certificate reqadmincert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(requestingAdminUsername)).iterator()
                .next();
        approvingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert));
        requestingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));
        
        final String approvalProfileName = RevocationApprovalTest.class.getSimpleName() + "_AccumulativeApprovalProfile";
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
        approvalProfile.setNumberOfApprovalsRequired(1);
        approvalProfileId = approvalProfileSession.addApprovalProfile(internalAdmin, approvalProfile);
        
        // Create new CA using approvals
        String caname = RevocationApprovalTest.class.getSimpleName();
        
        // Create new CA
        cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, caname, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        approvalCAID = createApprovalCA(internalAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, approvalProfileId, caAdminSession, caSession, catoken);
    }

    public String getRoleName() {
        return "RevocationApprovalTest";
    }

    private AuthenticationSubject makeAuthenticationSubject(X509Certificate certificate) {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(certificate.getSubjectX500Principal());
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);

        return new AuthenticationSubject(principals, credentials);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        try {
            endEntityManagementSession.deleteUser(internalAdmin, adminUsername);
        } catch (Exception e) {
            // NOPMD:
        }
        try {
            endEntityManagementSession.deleteUser(internalAdmin, requestingAdminUsername);
        } catch (Exception e) {
            // NOPMD:
        }
        caSession.removeCA(internalAdmin, approvalCAID);
        CryptoTokenTestUtils.removeCryptoToken(internalAdmin, cryptoTokenId);
        
        try {
            approvalProfileSession.removeApprovalProfile(internalAdmin, approvalProfileId);
        } catch (Exception e) {
            // NOPMD:
        }
        
        for(File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    private void createUser(AuthenticationToken admin, String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        endEntityManagementSession.addUser(admin, userdata, true);
        fileHandles.addAll(BatchCreateTool.createAllNew(internalAdmin, new File(P12_FOLDER_NAME)));
    }

    /**
     * Create a CA with one of the approval-requirements enabled.
     * 
     * @return the CA's ID.
     */
    public static int createApprovalCA(AuthenticationToken internalAdmin, String nameOfCA, int approvalRequirementType, int approvalProfileId,
            CAAdminSessionRemote caAdminSession, CaSessionRemote caSession, CAToken caToken) throws Exception {
        ArrayList<Integer> approvalSettings = new ArrayList<Integer>();
        approvalSettings.add(approvalRequirementType);
        X509CAInfo cainfo = new X509CAInfo("CN=" + nameOfCA, nameOfCA, CAConstants.CA_ACTIVE, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365,
                CAInfo.SELFSIGNED, null, caToken);
        cainfo.setExpireTime(new Date(System.currentTimeMillis() + 364 * 24 * 3600 * 1000));
        cainfo.setApprovalProfile(approvalProfileId);
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
        return caID;
    }

    /**
     * Verify that normal operations are working
     */
    @Test
    public void test01VerifyAddRemoveUser() throws Exception {
        String username = "test01Revocation";
        try {
            createUser(internalAdmin, username, approvalCAID);
            assertTrue("User was not created", endEntityManagementSession.existsUser(username));
        } catch(Exception e) {
            log.error("Failed in creating user", e);
            fail("Some form of error was encountered during end entity creation.");
        } finally {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }
        }
    }

    @Test
    public void test02RevokeUser() throws Exception {
        String username = "test02Revocation";
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                endEntityManagementSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                fail("WaitingForApprovalException should have been thrown to show that this action is waiting for approval.");
            } catch (ApprovalException e) {
                fail("Reporting that approval request exists, when it does not.");
            } catch (WaitingForApprovalException e) {
              //NOPMD Expected result
            }
            try {
                endEntityManagementSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                fail("ApprovalException should have been thrown to show that this action has already been submitted");
            } catch (ApprovalException e) {
              //NOPMD Expected result
            } catch (WaitingForApprovalException e) {
                fail("Allowing addition of identical approval requests.");
            }
            
            ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
            assertNotNull("Could not find approval profile with id: "+approvalProfileId, approvalProfile);
            int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, approvalCAID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
            // Make sure userstatus changed to revoked
            EndEntityInformation userdata = endEntityAccessSession.findUser(internalAdmin, username);
            assertTrue("User was not revoked when last cert was.", userdata.getStatus() == EndEntityConstants.STATUS_REVOKED);
        } finally {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }
        }
    }

    @Test
    public void test03RevokeAndDeleteUser() throws Exception {
        String username = "test03Revocation";
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                endEntityManagementSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                fail("WaitingForApprovalException should have been thrown to show that this action is waiting for approval.");
            } catch (ApprovalException e) {
                fail("Reporting that approval request exists, when it does not.");
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                fail("ApprovalException should have been thrown to show that this action has already been submitted");
            } catch (ApprovalException e) {
                //NOPMD Expected result
            } catch (WaitingForApprovalException e) {
                fail("Allowing addition of identical approval requests.");
            }
            ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
            assertNotNull("Could not find approval profile with id: "+approvalProfileId, approvalProfile);
            int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY, approvalCAID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
        } finally {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (NotFoundException e) {
                // This is what we expect if everything went ok
            }
        }
    } 

    @Test
    public void test04RevokeAndUnrevokeCertificateOnHold() throws Exception {
        String username = "test04Revocation";
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNONEXISTINGAPPROVALREPORTED = "Reporting that approval request exists, when it does not.";
        final String ERRORALLOWMORETHANONE = "Allowing more than one identical approval requests.";

        try {
            createUser(internalAdmin, username, approvalCAID);
            X509Certificate usercert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username)).iterator().next();
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                fail(ERRORNOTSENTFORAPPROVAL);
            } catch (ApprovalException e) {
                fail(ERRORNONEXISTINGAPPROVALREPORTED);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                fail(ERRORNOTSENTFORAPPROVAL);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                fail(ERRORALLOWMORETHANONE);
            }
            ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
            assertNotNull("Could not find approval profile with id: "+approvalProfileId, approvalProfile);
            int partitionId = approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, approvalCAID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
            assertEquals("Certificate was not revoked.", CertificateStatus.REVOKED, certificateStoreSession.getStatus(CertTools.getIssuerDN(usercert), CertTools.getSerialNumber(usercert)));
            // Unrevoke
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.NOT_REVOKED);
                fail(ERRORNOTSENTFORAPPROVAL);
            } catch (ApprovalException e) {
                fail(ERRORNONEXISTINGAPPROVALREPORTED);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.NOT_REVOKED);
                fail(ERRORNOTSENTFORAPPROVAL);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                fail(ERRORALLOWMORETHANONE);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED, ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE,
                    approvalCAID, approvalProfile, AccumulativeApprovalProfile.FIXED_STEP_ID, partitionId);
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }
    }
     
    @Test
    public void test05TestRequestIdInExtendedInformation() throws Exception {
        String username = "test01extendedInfoRevokeUser";
        
        // make sure that the end entity we are testing with does not already exist
        if(endEntityAccessSession.findUser(internalAdmin, username) != null) {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }

        String usercertfp="", usercert2fp="", usercert3fp="";
        try {
            
            createUser(internalAdmin, username, caid);
            X509Certificate usercert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username)).iterator().next();
            assertNotNull("Test user certificate was not created", usercert);

            RevocationApprovalRequest revAr = new RevocationApprovalRequest(CertTools.getSerialNumber(usercert), CertTools.getIssuerDN(usercert), username, 
                    RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, requestingAdmin, caid, SecConst.EMPTY_ENDENTITYPROFILE, null);
            revAr.execute(endEntityManagementSession, 4711);
            // Verify that the certificate was revokes
            usercert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username)).iterator().next();
            assertEquals("Certificate was not revoked.", CertificateStatus.REVOKED, certificateStoreSession.getStatus(CertTools.getIssuerDN(usercert), CertTools.getSerialNumber(usercert)));
            usercertfp = CertTools.getFingerprintAsString(usercert);

            EndEntityInformation executeUser = endEntityAccessSession.findUser(internalAdmin, username);
            
            // Verify that the end entity contains the approval request ID of the RevocationApprovalRequest
            ExtendedInformation ext = executeUser.getExtendedinformation();
            assertNotNull("end entity does not contain extended information", ext);
            List<Integer> revEEReqIds = ext.getRevokeEndEntityApprovalRequestIds();
            assertNotNull("Extended information does not contain the RevocationApprovalRequestIDs", revEEReqIds);
            assertEquals(1, revEEReqIds.size());
            assertEquals(Integer.valueOf(4711), revEEReqIds.get(0));
            
            // Issue two more certificate for this user and revoke the user. Verify that the end entity extended information has the correct approval IDs
            endEntityManagementSession.setClearTextPassword(internalAdmin, username, "foo123");
            endEntityManagementSession.setUserStatus(internalAdmin, username, EndEntityConstants.STATUS_NEW);
            KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            X509Certificate usercert2 = (X509Certificate) signSession.createCertificate(internalAdmin, username, "foo123", new PublicKeyWrapper(keys2.getPublic()));
            assertNotNull("Test user certificate was not created", usercert2);
            usercert2fp = CertTools.getFingerprintAsString(usercert2);
            
            endEntityManagementSession.setClearTextPassword(internalAdmin, username, "foo123");
            endEntityManagementSession.setUserStatus(internalAdmin, username, EndEntityConstants.STATUS_NEW);
            KeyPair keys3 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            X509Certificate usercert3 = (X509Certificate) signSession.createCertificate(internalAdmin, username, "foo123", new PublicKeyWrapper(keys3.getPublic()));
            assertNotNull("Test user certificate was not created", usercert3);
            usercert3fp = CertTools.getFingerprintAsString(usercert3);
            
            revAr = new RevocationApprovalRequest(false, username, RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, requestingAdmin, caid, SecConst.EMPTY_ENDENTITYPROFILE, null);
            revAr.execute(endEntityManagementSession, 4712);
            
            
            List<Certificate> usercerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
            assertEquals(3, usercerts.size());
            for(Certificate cert : usercerts) {
                assertEquals("Certificate was not revoked.", CertificateStatus.REVOKED, certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert)));
                if(CertTools.getSerialNumber(cert).equals(CertTools.getSerialNumber(usercert))) {
                    assertEquals("Certificate was not revoked.", RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert)).getRevocationReason());
                } else {
                    assertEquals("Certificate was not revoked.", RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED, certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert)).getRevocationReason());
                }
            }
            
            executeUser = endEntityAccessSession.findUser(internalAdmin, username);
            
            ext = executeUser.getExtendedinformation();
            assertNotNull("end entity does not contain extended information", ext);
            revEEReqIds = ext.getRevokeEndEntityApprovalRequestIds();
            assertNotNull("Extended information does not contain the RevocationApprovalRequestIDs", revEEReqIds);
            assertEquals(2, revEEReqIds.size());
            assertTrue(revEEReqIds.contains(Integer.valueOf(4711)));
            assertTrue(revEEReqIds.contains(Integer.valueOf(4712)));
            
            
        } finally {
            try {
                this.internalCertStoreSession.removeCertificate(usercertfp);
                this.internalCertStoreSession.removeCertificate(usercert2fp);
                this.internalCertStoreSession.removeCertificate(usercert3fp);
            } catch(Exception e) {} 

            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }
            
            
        }
    }
} 
