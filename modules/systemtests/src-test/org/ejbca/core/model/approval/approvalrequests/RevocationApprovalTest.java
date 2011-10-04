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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.Set;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class RevocationApprovalTest extends CaTestCase {

    private static String requestingAdminUsername = null;
    private static String adminUsername = null;

    private static final AuthenticationToken internalAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private static AuthenticationToken requestingAdmin = null;
    private static AuthenticationToken approvingAdmin = null;
    private static ArrayList<AccessUserAspectData> adminentities;
    
    private final String cliUserName = EjbcaConfiguration.getCliDefaultUser();
    private final String cliPassword = EjbcaConfiguration.getCliDefaultPassword();
    
    private AccessControlSessionRemote accessControlSession = InterfaceCache.getAccessControlSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private EndEntityAccessSessionRemote endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private ApprovalExecutionSessionRemote approvalExecutionSessionRemote = InterfaceCache.getApprovalExecutionSession();
    private ApprovalSessionRemote approvalSessionRemote = InterfaceCache.getApprovalSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    private final SimpleAuthenticationProviderRemote simpleAuthenticationProvider = JndiHelper.getRemoteSession(SimpleAuthenticationProviderRemote.class);
    
    private int caid = getTestCAId();
    private int approvalCAID;

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
        	EndEntityInformation userdata = new EndEntityInformation(adminUsername, "CN=" + adminUsername, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
        			SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        	userdata.setPassword("foo123");
        	userAdminSession.addUser(internalAdmin, userdata, true);
        	EndEntityInformation userdata2 = new EndEntityInformation(requestingAdminUsername, "CN=" + requestingAdminUsername, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
        			SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        	userdata2.setPassword("foo123");
        	userAdminSession.addUser(internalAdmin, userdata2, true);
        	BatchMakeP12 makep12 = new BatchMakeP12();
        	File tmpfile = File.createTempFile("ejbca", "p12");
        	makep12.setMainStoreDir(tmpfile.getParent());
        	makep12.createAllNew(cliUserName, cliPassword);
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
        adminentities.add(new AccessUserAspectData(getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, adminUsername));
        adminentities.add(new AccessUserAspectData(getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, requestingAdminUsername));
        roleManagementSession.addSubjectsToRole(internalAdmin, role, adminentities);
        accessControlSession.forceCacheExpire();
     
        X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminUsername).iterator().next();
        X509Certificate reqadmincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(requestingAdminUsername).iterator().next();
        approvingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert));
        requestingAdmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));
        // Create new CA using approvals
        String caname = RevocationApprovalTest.class.getSimpleName();
        approvalCAID = createApprovalCA(internalAdmin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession, caSession);
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
        	userAdminSession.deleteUser(internalAdmin, adminUsername);
        } catch (Exception e) {
        	// NOPMD:
        }
        try {
        	userAdminSession.deleteUser(internalAdmin, requestingAdminUsername);
        } catch (Exception e) {
        	// NOPMD:
        }
        caSession.removeCA(internalAdmin, approvalCAID);
    }

    private String genRandomUserName(String usernameBase) {
        usernameBase += (Integer.valueOf((new Random(new Date().getTime() + 4711)).nextInt(999999))).toString();
        return usernameBase;
    }

    private void createUser(AuthenticationToken admin, String username, int caID) throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        userAdminSession.addUser(admin, userdata, true);
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew(cliUserName, cliPassword);
    }


    /**
     * Create a CA with one of the approval-requirements enabled.
     * 
     * @return the CA's ID.
     */
    static public int createApprovalCA(AuthenticationToken internalAdmin, String nameOfCA, int approvalRequirementType, CAAdminSessionRemote caAdminSession, CaSessionRemote caSession)
            throws Exception {
        CATokenInfo catokeninfo = new CATokenInfo();
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catokeninfo.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catokeninfo.setClassPath(SoftCryptoToken.class.getName());
        Properties prop = catokeninfo.getProperties();
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, String.valueOf("512"));
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        catokeninfo.setProperties(prop);
        ArrayList<Integer> approvalSettings = new ArrayList<Integer>();
        approvalSettings.add(approvalRequirementType);
        X509CAInfo cainfo = new X509CAInfo("CN=" + nameOfCA, nameOfCA, SecConst.CA_ACTIVE, new Date(), "", SecConst.CERTPROFILE_FIXED_ROOTCA, 365, new Date(
                System.currentTimeMillis() + 364 * 24 * 3600 * 1000), CAInfo.CATYPE_X509, CAInfo.SELFSIGNED, null, catokeninfo, "Used for testing approvals",
                -1, null, null, 24, 0, 10, 0, new ArrayList<Integer>(), true, false, true, false, "", "", "", "", true, new ArrayList<ExtendedCAServiceInfo>(), false, approvalSettings, 1,
                false, true, false, false, true, true, true, false, true, true, true, null);
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
            userAdminSession.deleteUser(internalAdmin, username);
        }
    } // test01VerifyAddRemoveUser

    @Test
    public void test02RevokeUser() throws Exception {
        String username = genRandomUserName("test02Revocation");
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                userAdminSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
                assertTrue("Reporting that approval request exists, when it does not.", false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                userAdminSession.revokeUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue("Allowing addition of identical approval requests.", false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY, certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote, approvalCAID);
            // Make sure userstatus changed to revoked
            EndEntityInformation userdata = endEntityAccessSession.findUser(internalAdmin, username);
            assertTrue("User was not revoked when last cert was.", userdata.getStatus() == UserDataConstants.STATUS_REVOKED);
        } finally {
            userAdminSession.deleteUser(internalAdmin, username);
        }
    } // test02RevokeUser

    @Test
    public void test03RevokeAndDeleteUser() throws Exception {
        String username = genRandomUserName("test03Revocation");
        try {
            createUser(internalAdmin, username, approvalCAID);
            try {
                userAdminSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
                assertTrue("Reporting that approval request exists, when it does not.", false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                userAdminSession.revokeAndDeleteUser(requestingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
                assertTrue("Approval code never interrupted run.", false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue("Allowing addition of identical approval requests.", false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                    ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY, certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote, approvalCAID);
        } finally {
            try {
                userAdminSession.deleteUser(internalAdmin, username);
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
                userAdminSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
                assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                userAdminSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue(ERRORALLOWMORETHANONE, false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote, approvalCAID);
            // Unrevoke
            try {
                userAdminSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), RevokedCertInfo.NOT_REVOKED);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
                assertTrue(ERRORNONEXISTINGAPPROVALREPORTED, false);
            } catch (WaitingForApprovalException e) {
            }
            try {
                userAdminSession.revokeCert(requestingAdmin, usercert.getSerialNumber(), usercert.getIssuerDN().toString(), RevokedCertInfo.NOT_REVOKED);
                assertTrue(ERRORNOTSENTFORAPPROVAL, false);
            } catch (ApprovalException e) {
            } catch (WaitingForApprovalException e) {
                assertTrue(ERRORALLOWMORETHANONE, false);
            }
            approveRevocation(internalAdmin, approvingAdmin, username, RevokedCertInfo.NOT_REVOKED, ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE,
                    certificateStoreSession, approvalSessionRemote, approvalExecutionSessionRemote, approvalCAID);
        } finally {
            userAdminSession.deleteUser(internalAdmin, username);
        }
    } // test04RevokeAndUnrevokeCertificateOnHold


}
