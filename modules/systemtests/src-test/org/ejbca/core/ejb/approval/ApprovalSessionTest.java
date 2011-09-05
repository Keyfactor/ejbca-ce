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

package org.ejbca.core.ejb.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.approvalrequests.DummyApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id: ApprovalSessionTest.java 9666 2010-08-18 11:22:12Z mikekushner$
 */
public class ApprovalSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(ApprovalSessionTest.class);
    private static final AuthenticationToken intadmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private static final String roleName = "ApprovalTest";

    private static String reqadminusername = null;
    private static String adminusername1 = null;
    private static String adminusername2 = null;

    private static X509Certificate reqadmincert = null;
    private static X509Certificate admincert1 = null;
    private static X509Certificate admincert2 = null;
    private static X509Certificate externalcert = null;

    private static AuthenticationToken reqadmin = null;
    private static AuthenticationToken admin1 = null;
    private static AuthenticationToken admin2 = null;
    private static AuthenticationToken externaladmin = null;

    private RoleData role;

    private static ArrayList<AccessUserAspectData> adminentities;
    private static GlobalConfiguration gc = null;

    private int caid = getTestCAId();

    private int removeApprovalId = 0;
    
    private AccessControlSessionRemote accessControlSession = InterfaceCache.getAccessControlSession();
    private RoleManagementSessionRemote roleManagementSession = InterfaceCache.getRoleManagementSession();
    private RoleAccessSessionRemote roleAccessSessionRemote = InterfaceCache.getRoleAccessSession();
    private ApprovalSessionRemote approvalSessionRemote = InterfaceCache.getApprovalSession();
    private ApprovalExecutionSessionRemote approvalExecutionSessionRemote = InterfaceCache.getApprovalExecutionSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    public void init() throws Exception {

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // An if on a static thing here, just so we don't have to batch generate new certs for every test
        if (adminusername1 == null) {
            adminusername1 = genRandomUserName();
            adminusername2 = adminusername1 + "2";
            reqadminusername = "req" + adminusername1;

            EndEntityInformation userdata = new EndEntityInformation(adminusername1, "CN=" + adminusername1, caid, null, null, 1,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            userAdminSession.addUser(intadmin, userdata, true);

            EndEntityInformation userdata2 = new EndEntityInformation(adminusername2, "CN=" + adminusername2, caid, null, null, 1,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata2.setPassword("foo123");
            userAdminSession.addUser(intadmin, userdata2, true);

            EndEntityInformation userdata3 = new EndEntityInformation(reqadminusername, "CN=" + reqadminusername, caid, null, null, 1,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata3.setPassword("foo123");
            userAdminSession.addUser(intadmin, userdata3, true);

            KeyPair rsakey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            externalcert = CertTools.genSelfCert("CN=externalCert,C=SE", 30, null, rsakey.getPrivate(), rsakey.getPublic(),
                    AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
            externaladmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(externalcert));

            File tmpfile = File.createTempFile("ejbca", "p12");
            BatchMakeP12 makep12 = new BatchMakeP12();
            makep12.setMainStoreDir(tmpfile.getParent());
            makep12.createAllNew();
            tmpfile.delete();
        }
        role = roleAccessSessionRemote.findRole(roleName);
        if (role == null) {
        	role = roleManagementSession.create(intadmin, roleName);
        }

        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(roleName, AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(roleName, StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
        
        adminentities = new ArrayList<AccessUserAspectData>();
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS,
        		adminusername1));
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS,
        		adminusername2));
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS,
        		reqadminusername));
        adminentities.add(new AccessUserAspectData(role.getRoleName(), "CN=externalCert,C=SE".hashCode(), AccessMatchValue.WITH_SERIALNUMBER,
        		AccessMatchType.TYPE_EQUALCASEINS, CertTools.getSerialNumberAsString(externalcert)));
        roleManagementSession.addSubjectsToRole(intadmin, roleAccessSessionRemote.findRole(roleName), adminentities);
        accessControlSession.forceCacheExpire();

        admincert1 = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminusername1).iterator().next();
        admincert2 = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminusername2).iterator().next();
        reqadmincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(reqadminusername).iterator().next();

        admin1 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert1));
        admin2 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert2));
        reqadmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));
        // TODO: before is had both a cert and username input?

        gc = globalConfigurationSession.getCachedGlobalConfiguration(intadmin);
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
        Collection<ApprovalDataVO> approvals = approvalSessionRemote.findApprovalDataVO(intadmin, removeApprovalId);
        if (approvals != null) {
        	for (ApprovalDataVO approvalDataVO : approvals) {
				approvalSessionRemote.removeApprovalRequest(intadmin, approvalDataVO.getId());
			}
        }
        try {
        	userAdminSession.deleteUser(intadmin, adminusername1);
        } catch (Exception e) {
        	// NOPMD: ignore
        }
        try {
        	userAdminSession.deleteUser(intadmin, adminusername2);
        } catch (Exception e) {
        	// NOPMD: ignore
        }
        try {
        	userAdminSession.deleteUser(intadmin, reqadminusername);
        } catch (Exception e) {
        	// NOPMD: ignore
        }
        roleManagementSession.remove(intadmin, role);

    }

    @Test
    public void testAddApprovalRequest() throws Exception {

        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        Certificate cert = nonExecutableRequest.getRequestAdminCert();
        assertEquals(CertTools.getIssuerDN(reqadmincert), CertTools.getIssuerDN(cert));
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        
        List<Integer> cleanUpList = new ArrayList<Integer>();
        
        try {
            // Test that the approval request does not exist.
            Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
            assertEquals(0, result.size());
            approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

            // Test that the approvalRequest exists now
            result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
            assertTrue(result.size() == 1);

            ApprovalDataVO next = result.iterator().next();
            cleanUpList.add(next.getId());
            assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, next.getStatus());
            assertEquals(caid, next.getCAId());
            assertEquals(SecConst.EMPTY_ENDENTITYPROFILE, next.getEndEntityProfileiId());
            assertEquals(CertTools.getIssuerDN(reqadmincert), next.getReqadmincertissuerdn());
            assertEquals(CertTools.getSerialNumberAsString(reqadmincert), next.getReqadmincertsn());
            assertEquals(nonExecutableRequest.generateApprovalId(), next.getApprovalId());
            assertEquals(nonExecutableRequest.getApprovalType(), next.getApprovalType());
            assertEquals(0, next.getApprovals().size());
            assertFalse(next.getApprovalRequest().isExecutable());
            assertEquals(2, next.getRemainingApprovals());

            // Test that the request expires as it should
            Thread.sleep(5000);
            result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
            assertTrue(result.size() == 1);

            next = (ApprovalDataVO) result.iterator().next();
            cleanUpList.add(next.getId());
            assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_EXPIRED);

            // Test to add the same action twice
            approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);
            try {
                approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);
                fail("It shouldn't be possible to add two identical requests.");
            } catch (ApprovalException e) {
            }

            // Then after one of them have expired
            Thread.sleep(5000);
            result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
            ApprovalDataVO expired = (ApprovalDataVO) result.iterator().next();

            approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

            approvalSessionRemote.removeApprovalRequest(admin1, expired.getId());

            result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        } finally {
            for (Integer next : cleanUpList) {
                approvalSessionRemote.removeApprovalRequest(admin1, next);
            }
        }
    }

    @Test
    public void testApprove() throws Exception {

        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

        Approval approval1 = new Approval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approval1, gc);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);

        ApprovalDataVO next = result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
        assertTrue(next.getRemainingApprovals() == 1);

        Approval approvalAgain = new Approval("apAgaintest");
        try {
            approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approvalAgain, gc);
            fail("The same admin shouldn't be able to approve a request twice");
        } catch (AdminAlreadyApprovedRequestException e) {
        }

        Approval approval2 = new Approval("ap2test");
        approvalExecutionSessionRemote.approve(admin2, nonExecutableRequest.generateApprovalId(), approval2, gc);

        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);

        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_APPROVED);
        assertTrue(next.getRemainingApprovals() == 0);

        // Test that the approval exipres as it should
        Thread.sleep(5000);
        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);

        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_EXPIRED);

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        // Test using an executable Dummy, different behaviour
        DummyApprovalRequest executableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, true);
        approvalSessionRemote.addApprovalRequest(admin1, executableRequest, gc);

        approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approval1, gc);
        approvalExecutionSessionRemote.approve(admin2, nonExecutableRequest.generateApprovalId(), approval2, gc);

        result = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
        assertTrue(result.size() == 1);
        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_EXECUTED);

        // Make sure that the approval still have status executed after
        // exiration
        Thread.sleep(5000);
        result = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
        assertTrue(result.size() == 1);

        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_EXECUTED);

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        // Test to request and to approve with the same admin
        nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);
        Approval approvalUsingReqAdmin = new Approval("approvalUsingReqAdmin");
        try {
            approvalExecutionSessionRemote.approve(reqadmin, nonExecutableRequest.generateApprovalId(), approvalUsingReqAdmin, gc);
            fail("Request admin shouln't be able to approve their own request");
        } catch (AdminAlreadyApprovedRequestException e) {
        }
        result = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
        assertTrue(result.size() == 1);
        next = (ApprovalDataVO) result.iterator().next();
        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

    }

    @Test
    public void testReject() throws Exception {
        log.trace(">testReject()");
        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest, gc);

        Approval approval1 = new Approval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approval1, gc);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        ApprovalDataVO next = result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
        assertTrue(next.getRemainingApprovals() == 1);

        Approval rejection = new Approval("rejectiontest");
        approvalSessionRemote.reject(admin2, nonExecutableRequest.generateApprovalId(), rejection, gc);
        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_REJECTED);
        assertTrue(next.getRemainingApprovals() == 0);

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest, gc);

        rejection = new Approval("rejectiontest2");
        approvalSessionRemote.reject(admin1, nonExecutableRequest.generateApprovalId(), rejection, gc);
        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_REJECTED);
        assertTrue(next.getRemainingApprovals() == 0);

        // Try to approve a rejected request
        try {
            approvalExecutionSessionRemote.approve(admin2, nonExecutableRequest.generateApprovalId(), approval1, gc);
            fail("It shouldn't be possible to approve a rejected request");
        } catch (ApprovalException e) {
            log.info("ApprovalException: " + e.getErrorCode() + ". " + e.getMessage());
        } catch (EjbcaException e) {
            log.info("EjbcaException: " + e.getErrorCode() + ". " + e.getMessage());
        }

        // Test that the approval exipres as it should
        Thread.sleep(5000);
        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);

        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_EXPIRED);

        // Try to reject an expired request
        try {
            approvalSessionRemote.reject(admin2, nonExecutableRequest.generateApprovalId(), rejection, gc);
            fail("It shouln't be possible to reject and expired request");
        } catch (ApprovalException e) {
        }

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());
        log.trace("<testReject()");
    }

    @Test
    public void testIsApproved() throws Exception {
        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest, gc);

        int status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId());
        assertTrue(status == 2);

        Approval approval1 = new Approval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approval1, gc);

        status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId());
        assertTrue(status == 1);

        Approval approval2 = new Approval("ap2test");
        approvalExecutionSessionRemote.approve(admin2, nonExecutableRequest.generateApprovalId(), approval2, gc);

        status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId());
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        // Test that the approval exipres as it should
        Thread.sleep(5000);

        try {
            status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId());
            fail("A ApprovalRequestExpiredException should be thrown here");
        } catch (ApprovalRequestExpiredException e) {
        }

        status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId());
        assertTrue(status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        ApprovalDataVO next = result.iterator().next();

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

    }

    @Test
    public void testIsApprovedWithSteps() throws Exception {
        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, 3, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest, gc);

        int status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId(), 0);
        assertTrue(status == 2);

        int approvalId = nonExecutableRequest.generateApprovalId();
        Approval approval1 = new Approval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, approvalId, approval1, gc);

        status = approvalSessionRemote.isApproved(reqadmin, nonExecutableRequest.generateApprovalId(), 0);
        assertTrue(status == 1);

        Approval approval2 = new Approval("ap2test");
        approvalExecutionSessionRemote.approve(admin2, approvalId, approval2, gc);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 0);
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 1);
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 2);
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        approvalSessionRemote.markAsStepDone(reqadmin, approvalId, 0);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 0);
        assertTrue(status == ApprovalDataVO.STATUS_EXPIRED);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 1);
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        approvalSessionRemote.markAsStepDone(reqadmin, approvalId, 1);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 0);
        assertTrue(status == ApprovalDataVO.STATUS_EXPIRED);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 1);
        assertTrue(status == ApprovalDataVO.STATUS_EXPIRED);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 2);
        assertTrue(status == ApprovalDataVO.STATUS_APPROVED);

        approvalSessionRemote.markAsStepDone(reqadmin, approvalId, 2);

        status = approvalSessionRemote.isApproved(reqadmin, approvalId, 2);
        assertTrue(status == ApprovalDataVO.STATUS_EXPIRED);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        ApprovalDataVO next = result.iterator().next();

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

    }

    @Test
    public void testFindNonExpiredApprovalRequest() throws Exception {
        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();

        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

        // Then after one of them have expired
        Thread.sleep(5000);

        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

        ApprovalDataVO result = approvalSessionRemote.findNonExpiredApprovalRequest(admin1, nonExecutableRequest.generateApprovalId());
        assertNotNull(result);
        assertTrue(result.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);

        Collection<ApprovalDataVO> all = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        Iterator<ApprovalDataVO> iter = all.iterator();
        while (iter.hasNext()) {
            ApprovalDataVO next = iter.next();
            approvalSessionRemote.removeApprovalRequest(admin1, next.getId());
        }

    }

    @Test
    public void testQuery() throws Exception {

        // Add a few requests
        DummyApprovalRequest req1 = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        DummyApprovalRequest req2 = new DummyApprovalRequest(admin1, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        DummyApprovalRequest req3 = new DummyApprovalRequest(admin2, null, 3, 2, false);

        approvalSessionRemote.addApprovalRequest(admin1, req1, gc);
        approvalSessionRemote.addApprovalRequest(admin1, req2, gc);
        approvalSessionRemote.addApprovalRequest(admin1, req3, gc);

        // Make som queries
        Query q1 = new Query(Query.TYPE_APPROVALQUERY);
        q1.add(ApprovalMatch.MATCH_WITH_APPROVALTYPE, BasicMatch.MATCH_TYPE_EQUALS, "" + req1.getApprovalType());

        List result = approvalSessionRemote.query(admin1, q1, 0, 3, "cAId=" + caid, "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 2 && result.size() <= 3);

        result = approvalSessionRemote.query(admin1, q1, 1, 3, "cAId=" + caid, "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 1 && result.size() <= 3);

        result = approvalSessionRemote.query(admin1, q1, 0, 1, "cAId=" + caid, "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() == 1);

        Query q2 = new Query(Query.TYPE_APPROVALQUERY);
        q2.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, "" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, Query.CONNECTOR_AND);
        q2.add(ApprovalMatch.MATCH_WITH_REQUESTADMINCERTSERIALNUMBER, BasicMatch.MATCH_TYPE_EQUALS, reqadmincert.getSerialNumber().toString(16));

        result = approvalSessionRemote.query(admin1, q1, 1, 3, "cAId=" + caid, "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 1 && result.size() <= 3);

        // Remove the requests
        int id1 = ((ApprovalDataVO) approvalSessionRemote.findApprovalDataVO(admin1, req1.generateApprovalId()).iterator().next()).getId();
        int id2 = ((ApprovalDataVO) approvalSessionRemote.findApprovalDataVO(admin1, req2.generateApprovalId()).iterator().next()).getId();
        int id3 = ((ApprovalDataVO) approvalSessionRemote.findApprovalDataVO(admin1, req3.generateApprovalId()).iterator().next()).getId();
        approvalSessionRemote.removeApprovalRequest(admin1, id1);
        approvalSessionRemote.removeApprovalRequest(admin1, id2);
        approvalSessionRemote.removeApprovalRequest(admin1, id3);
    }

    @Test
    public void testApprovalsWithExternalAdmins() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            InvalidKeyException, CertificateEncodingException, SignatureException, IllegalStateException, ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, EjbcaException {
        log.trace(">testApprovalsWithExternalAdmins()");
        DummyApprovalRequest nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, false);
        removeApprovalId = nonExecutableRequest.generateApprovalId();
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest, gc);

        Approval approval1 = new Approval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, nonExecutableRequest.generateApprovalId(), approval1, gc);
        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);
        ApprovalDataVO next = result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
        assertTrue(next.getRemainingApprovals() == 1);

        Approval approval2 = new Approval("ap2test");
        approvalExecutionSessionRemote.approve(externaladmin, nonExecutableRequest.generateApprovalId(), approval2, gc);
        result = approvalSessionRemote.findApprovalDataVO(admin1, nonExecutableRequest.generateApprovalId());
        assertTrue(result.size() == 1);
        next = (ApprovalDataVO) result.iterator().next();
        assertTrue("Status = " + next.getStatus(), next.getStatus() == ApprovalDataVO.STATUS_APPROVED);
        assertTrue(next.getRemainingApprovals() == 0);

        log.trace("<testApprovalsWithExternalAdmins()");
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

}
