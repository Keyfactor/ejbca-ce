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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

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
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class RevocationApprovalTest extends CaTestCase {

    private static String requestingAdminUsername = null;
    private static String adminUsername = null;

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "RevocationApprovalTest"));
    private static AuthenticationToken requestingAdmin = null;
    private static AuthenticationToken approvingAdmin = null;
    private static ArrayList<AccessUserAspectData> adminentities;

    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ApprovalExecutionSessionRemote approvalExecutionSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(ApprovalExecutionSessionRemote.class);
    private ApprovalSessionRemote approvalSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
            SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private int caid = getTestCAId();
    private int approvalCAID;
    private int cryptoTokenId = 0;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // An if on a static thing here, just so we don't have to batch generate new certs for every test
        if (adminUsername == null) {
            adminUsername = genRandomUserName("revocationTestAdmin");
            requestingAdminUsername = genRandomUserName("revocationTestRequestingAdmin");
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
            File tmpfile = File.createTempFile("ejbca", "p12");
            BatchCreateTool.createAllNew(internalAdmin, tmpfile.getParent());
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

        X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminUsername).iterator().next();
        X509Certificate reqadmincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(requestingAdminUsername).iterator()
                .next();
        approvingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert));
        requestingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));
        // Create new CA using approvals
        String caname = RevocationApprovalTest.class.getSimpleName();

        // Create new CA
        cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, caname, "1024");
        final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        approvalCAID = createApprovalCA(internalAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession, caSession, catoken);
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
    }

    private String genRandomUserName(String usernameBase) {
        usernameBase += (Integer.valueOf((new Random(new Date().getTime() + 4711)).nextInt(999999))).toString();
        return usernameBase;
    }

    private void createUser(AuthenticationToken admin, String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        endEntityManagementSession.addUser(admin, userdata, true);
        File tmpfile = File.createTempFile("ejbca", "p12");
        BatchCreateTool.createAllNew(internalAdmin, tmpfile.getParent());
    }

    /**
     * Create a CA with one of the approval-requirements enabled.
     * 
     * @return the CA's ID.
     */
    static public int createApprovalCA(AuthenticationToken internalAdmin, String nameOfCA, int approvalRequirementType,
            CAAdminSessionRemote caAdminSession, CaSessionRemote caSession, CAToken caToken) throws Exception {
        final List<Integer> approvalSettings = new ArrayList<Integer>();
        approvalSettings.add(approvalRequirementType);
        X509CAInfo cainfo = new X509CAInfo("CN=" + nameOfCA, nameOfCA, CAConstants.CA_ACTIVE, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 365,
                CAInfo.SELFSIGNED, null, caToken);
        cainfo.setExpireTime(new Date(System.currentTimeMillis() + 364 * 24 * 3600 * 1000));
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
        String username = genRandomUserName("test01Revocation");
        try {
            createUser(internalAdmin, username, approvalCAID);
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }
    } // test01VerifyAddRemoveUser

    @Test
    public void test02RevokeUser() throws Exception {
        String username = genRandomUserName("test02Revocation");
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                endEntityManagementSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
                assertTrue("Reporting that approval request exists, when it does not.", false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue("Allowing addition of identical approval requests.", false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote,
                    approvalCAID);
            // Make sure userstatus changed to revoked
            EndEntityInformation userdata = endEntityAccessSession.findUser(internalAdmin, username);
            assertTrue("User was not revoked when last cert was.", userdata.getStatus() == EndEntityConstants.STATUS_REVOKED);
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }
    } // test02RevokeUser

    @Test
    public void test03RevokeAndDeleteUser() throws Exception {
        String username = genRandomUserName("test03Revocation");
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                endEntityManagementSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
                assertTrue("Reporting that approval request exists, when it does not.", false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue("Allowing addition of identical approval requests.", false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY, certificateStoreSession, approvalSessionRemote,
                    approvalExecutionSessionRemote, approvalCAID);
        } finally {
            try {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            } catch (NotFoundException e) {
                // This is what we expect if everything went ok
            }
        }
    } // test03RevokeAndDeleteUser

    @Test
    public void test04RevokeAndUnrevokeCertificateOnHold() throws Exception {
        String username = genRandomUserName("test04Revocation");
        final String ERRORNOTSENTFORAPPROVAL = "The request was never sent for approval.";
        final String ERRORNONEXISTINGAPPROVALREPORTED = "Reporting that approval request exists, when it does not.";
        final String ERRORALLOWMORETHANONE = "Allowing more than one identical approval requests.";
        try {
            createUser(internalAdmin, username, approvalCAID);
            X509Certificate usercert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(username).iterator().next();
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
                assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue(ERRORALLOWMORETHANONE, false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote,
                    approvalCAID);
            // Unrevoke
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.NOT_REVOKED);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
                assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                endEntityManagementSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.NOT_REVOKED);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue(ERRORALLOWMORETHANONE, false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED, ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE,
                    certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote, approvalCAID);
        } finally {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }
    } // test04RevokeAndUnrevokeCertificateOnHold

}
