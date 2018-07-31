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

package org.ejbca.core.ejb.approval;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.TimeMatch;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Test of approvals.
 * <p>
 * Note/TODO:
 * A lot of tests in this class is written in such a way that they are sensitive to timing on a highly loaded test
 * server. This needs to rewritten in a more robust way at a future point in time to avoid false negatives.
 * </p>
 *
 * @version $Id$
 */
public class ApprovalSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(ApprovalSessionTest.class);
    private static final AuthenticationToken intadmin = new TestAlwaysAllowLocalAuthenticationToken(ApprovalSessionTest.class.getSimpleName());

    private static final String P12_FOLDER_NAME = "p12";

    private static final String roleName = "ApprovalTest";

    private static String adminusername1 = "createTestCAWithEndEntity";
    private static String adminusername2 = adminusername1 + "2";
    private static String adminusername3 = adminusername1 + "3";
    private static String reqadminusername = "req" + adminusername1;

    private static X509Certificate reqadmincert = null;
    private static X509Certificate admincert1 = null;
    private static X509Certificate admincert2 = null;
    private static X509Certificate admincert3 = null;
    private static X509Certificate externalcert = null;

    private static AuthenticationToken reqadmin = null;
    private static AuthenticationToken admin1 = null;
    private static AuthenticationToken admin2 = null;
    private static AuthenticationToken admin3 = null;
    private static AuthenticationToken externaladmin = null;

    private static AccumulativeApprovalProfile approvalProfile = null;
    private static List<File> fileHandles = new ArrayList<>();
    private final SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
            SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            ApprovalProfileSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private Role role;
    private int caid = getTestCAId();
    private long originalValidity = 0L;
    // Identifiers of temporary instances to be removed after a test
    private List<Integer> removeApprovalIds = new ArrayList<>();
    private DummyApprovalRequest nonExecutableRequest;
    private String removeUserName = null;
    private ApprovalSessionRemote approvalSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private ApprovalSessionProxyRemote approvalSessionProxyRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionProxyRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private ApprovalExecutionSessionRemote approvalExecutionSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(ApprovalExecutionSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA();
        approvalProfile = new AccumulativeApprovalProfile("AccumulativeApprovalProfile");
        approvalProfile.setNumberOfApprovalsRequired(2);
        approvalProfile.setMaxExtensionTime(0);
        ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
        int approvalProfileId = approvalProfileSession.addApprovalProfile(intadmin, approvalProfile);
        approvalProfile.setProfileId(approvalProfileId);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        removeTestCA();
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificate(admincert1);
        internalCertificateStoreSession.removeCertificate(admincert2);
        internalCertificateStoreSession.removeCertificate(admincert3);
        internalCertificateStoreSession.removeCertificate(externalcert);
        internalCertificateStoreSession.removeCertificate(reqadmincert);

        ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
        if ((approvalProfile.getProfileId() != null) && (approvalProfileSession.getApprovalProfile(approvalProfile.getProfileId()) != null)) {
            approvalProfileSession.removeApprovalProfile(intadmin, approvalProfile);
        }

        for (File file : fileHandles) {
            FileTools.delete(file);
        }
    }

    @Before
    public void createTestCAWithEndEntity() throws Exception {
        EndEntityInformation userdata = new EndEntityInformation(adminusername1, "CN=" + adminusername1, caid, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        endEntityManagementSession.addUser(intadmin, userdata, true);

        EndEntityInformation userdata2 = new EndEntityInformation(adminusername2, "CN=" + adminusername2, caid, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata2.setPassword("foo123");
        endEntityManagementSession.addUser(intadmin, userdata2, true);

        EndEntityInformation userdata3 = new EndEntityInformation(adminusername3, "CN=" + adminusername3, caid, null, null, new EndEntityType(
                EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata3.setPassword("foo123");
        endEntityManagementSession.addUser(intadmin, userdata3, true);

        EndEntityInformation reqUserData = new EndEntityInformation(reqadminusername, "CN=" + reqadminusername, caid, null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        reqUserData.setPassword("foo123");
        endEntityManagementSession.addUser(intadmin, reqUserData, true);

        KeyPair rsakey = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        externalcert = CertTools.genSelfCert("CN=externalCert,C=SE", 30, null, rsakey.getPrivate(), rsakey.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        externaladmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(externalcert));

        fileHandles.addAll(BatchCreateTool.createAllNew(intadmin, new File(P12_FOLDER_NAME)));

        final Role oldRole = roleSession.getRole(intadmin, null, roleName);
        if (oldRole != null) {
            roleSession.deleteRoleIdempotent(intadmin, oldRole.getRoleId());
        }
        role = roleSession.persistRole(intadmin, new Role(null, roleName, Arrays.asList(
                AccessRulesConstants.REGULAR_APPROVEENDENTITY,
                AccessRulesConstants.ENDENTITYPROFILEBASE,
                StandardRules.CAACCESSBASE.resource()
        ), null));
        roleMemberSession.persist(intadmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), adminusername1, role.getRoleId(), null));
        roleMemberSession.persist(intadmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), adminusername2, role.getRoleId(), null));
        roleMemberSession.persist(intadmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), adminusername3, role.getRoleId(), null));
        roleMemberSession.persist(intadmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), reqadminusername, role.getRoleId(), null));
        roleMemberSession.persist(intadmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                "CN=externalCert,C=SE".hashCode(), X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), CertTools.getSerialNumberAsString(externalcert), role.getRoleId(), null));

        admincert1 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername1)).iterator().next();
        admincert2 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername2)).iterator().next();
        admincert3 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername3)).iterator().next();
        reqadmincert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(reqadminusername)).iterator().next();

        admin1 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert1));
        admin2 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert2));
        admin3 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert3));
        reqadmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));

        // TODO: before is had both a cert and username input?

        originalValidity = approvalProfile.getRequestExpirationPeriod();
        approvalProfile.setApprovalExpirationPeriod(1000);
        approvalProfile.setRequestExpirationPeriod(1000);
        approvalProfileSession.changeApprovalProfile(intadmin, approvalProfile);
        nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, false, approvalProfile);
        removeApprovalIds = new ArrayList<>();
        removeApprovalIds.add(nonExecutableRequest.generateApprovalId());
    }

    @After
    public void tearDown() throws Exception {
        // Reset profile
        approvalProfile.setNumberOfApprovalsRequired(2);
        approvalProfile.setMaxExtensionTime(0);
        approvalProfile.setApprovalExpirationPeriod(originalValidity);
        approvalProfile.setRequestExpirationPeriod(originalValidity);
        approvalProfileSession.changeApprovalProfile(intadmin, approvalProfile);
        //
        for (int removeApprovalId : removeApprovalIds) {
            Collection<ApprovalDataVO> approvals = approvalSessionRemote.findApprovalDataVO(removeApprovalId);
            if (approvals != null && !approvals.isEmpty()) {
                for (ApprovalDataVO approvalDataVO : approvals) {
                    approvalSessionRemote.removeApprovalRequest(intadmin, approvalDataVO.getId());
                }
            }
        }
        for (final String username : Arrays.asList(adminusername1, adminusername2, adminusername3, reqadminusername)) {
            try {
                endEntityManagementSession.deleteUser(intadmin, username);
            } catch (Exception e) {
                // NOPMD: ignore
            }
        }
        if (role != null) {
            roleSession.deleteRoleIdempotent(intadmin, role.getRoleId());
        }
        if (removeUserName != null) {
            endEntityManagementSession.deleteUser(intadmin, removeUserName);
        }
    }

    @Test
    public void testAddApprovalRequest() throws Exception {
        log.trace(">testAddApprovalRequest");
        int approvalId = removeApprovalIds.get(0);
        Certificate cert = nonExecutableRequest.getRequestAdminCert();
        assertEquals(CertTools.getIssuerDN(reqadmincert), CertTools.getIssuerDN(cert));

        // Test that the approval request does not exist.
        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(0, result.size());
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);

        // Test that the approvalRequest exists now
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());

        ApprovalDataVO next = result.iterator().next();
        assertEquals("Status was expired and not waiting.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, next.getStatus());
        assertEquals(caid, next.getCAId());
        assertEquals(EndEntityConstants.EMPTY_END_ENTITY_PROFILE, next.getEndEntityProfileId());
        assertEquals(CertTools.getIssuerDN(reqadmincert), next.getReqadmincertissuerdn());
        assertEquals(CertTools.getSerialNumberAsString(reqadmincert), next.getReqadmincertsn());
        assertEquals(approvalId, next.getApprovalId());
        assertEquals(nonExecutableRequest.getApprovalType(), next.getApprovalType());
        assertEquals(0, next.getApprovals().size());
        assertFalse(next.getApprovalRequest().isExecutable());
        assertEquals(2, next.getRemainingApprovals());
        Thread.sleep(1100);
        // Test that the request expires as it should
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals("Request should not expire", 1, result.size());

        next = result.iterator().next();
        assertEquals("Status was not expired.", ApprovalDataVO.STATUS_EXPIRED, next.getStatus());

        // Then after one of them have expired
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        ApprovalDataVO expired = result.iterator().next();

        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);

        approvalSessionRemote.removeApprovalRequest(admin1, expired.getId());

        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals("Should contain the approval request after removal of expired", 1, result.size());

        // Test approvalId generation with a "real" approval request with a requestAdmin
        approvalProfile.setNumberOfApprovalsRequired(1);
        ViewHardTokenDataApprovalRequest ar = new ViewHardTokenDataApprovalRequest("APPROVALREQTESTTOKENUSER1",
                "CN=APPROVALREQTESTTOKENUSER1", "12345678", true, reqadmin, null, 1, 0, 0, approvalProfile);
        log.debug("Adding approval with approvalID (hash): " + ar.generateApprovalId());
        approvalSessionRemote.addApprovalRequest(admin1, ar);
        result = approvalSessionRemote.findApprovalDataVO(ar.generateApprovalId());
        assertEquals("Should contain the approval request", 1, result.size());
        log.trace("<testAddApprovalRequest");
    }

    @Test
    public void testApprove() throws Exception {
        log.trace(">testApprove");
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);

        final Approval approval1 = createApproval("ap1test");
        final Approval approval2 = createApproval("ap2test");
        approvalExecutionSessionRemote.approve(admin1, approvalId, approval1);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals("Wrong number of approval requests was returned.", 1, result.size());

        ApprovalDataVO next = result.iterator().next();
        assertEquals("Status was not set to 'Waiting for Approval'", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, next.getStatus());
        assertEquals("Wrong number of remaining approvals", 1, next.getRemainingApprovals());

        approvalExecutionSessionRemote.approve(admin2, approvalId, approval2);

        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());

        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_APPROVED, next.getStatus());
        assertEquals(0, next.getRemainingApprovals());

        // Test that the approval expires as it should
        Thread.sleep(1100);
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());

        next = result.iterator().next();
        assertEquals("Status was not expired.", ApprovalDataVO.STATUS_EXPIRED, next.getStatus());

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        // Test using an executable Dummy, different behaviour
        final DummyApprovalRequest executableRequest = new DummyApprovalRequest(reqadmin, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, true, approvalProfile);
        int executableApprovalId = executableRequest.generateApprovalId();
        removeApprovalIds.add(executableApprovalId);
        approvalSessionRemote.addApprovalRequest(admin1, executableRequest);

        approvalExecutionSessionRemote.approve(admin1, approvalId, approval1);
        approvalExecutionSessionRemote.approve(admin2, approvalId, approval2);

        result = approvalSessionRemote.findApprovalDataVO(executableApprovalId);
        assertEquals(1, result.size());
        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_EXECUTED, next.getStatus());

        // Make sure that the approval still have status executed after expiration
        Thread.sleep(1100);
        result = approvalSessionRemote.findApprovalDataVO(executableApprovalId);
        assertEquals(1, result.size());
        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_EXECUTED, next.getStatus());

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());
        log.trace("<testApprove");
    }

    @Test
    public void testApproveFromCli() throws Exception {
        log.trace(">testApproveFromCli");
        final AuthenticationToken cliReqAuthToken = getCliAdmin();
        final String username = "ApprovalEndEntityUsername";
        removeUserName = username;
        final EndEntityInformation userdata = new EndEntityInformation(username, "C=SE, O=AnaTom, CN=" + username, caid, null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        approvalProfile.setNumberOfApprovalsRequired(1);
        final AddEndEntityApprovalRequest eeApprovalRequest = new AddEndEntityApprovalRequest(userdata, false, cliReqAuthToken, null, caid,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, approvalProfile);
        int approvalId = eeApprovalRequest.generateApprovalId();
        removeApprovalIds.add(approvalId);
        approvalSessionRemote.addApprovalRequest(cliReqAuthToken, eeApprovalRequest);
        // Use the authentication token
        endEntityManagementSession.addUser(intadmin, userdata, false);
        endEntityManagementSession.changeUser(cliReqAuthToken, userdata, false);
        approvalExecutionSessionRemote.approve(intadmin, approvalId, createApproval("ap1test"));

        final int actualStatus = approvalSessionRemote.isApproved(approvalId);
        assertEquals(ApprovalDataVO.STATUS_APPROVED, actualStatus);
        log.trace("<testApproveFromCli");
    }

    @Test
    public void testReject() throws Exception {
        log.trace(">testReject()");
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest);

        final Approval approval1 = createApproval("ap1test");
        approvalExecutionSessionRemote.approve(admin1, approvalId, approval1);

        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(approvalId);
        ApprovalDataVO next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, next.getStatus());
        assertEquals(1, next.getRemainingApprovals());

        Approval rejection = createApproval("rejectiontest");
        approvalExecutionSessionRemote.reject(admin2, approvalId, rejection);
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_REJECTED, next.getStatus());
        assertEquals("No approvals expected to be required.", 0, next.getRemainingApprovals());

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        nonExecutableRequest = new DummyApprovalRequest(reqadmin, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, false, approvalProfile);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest);

        rejection = createApproval("rejectiontest2");
        approvalExecutionSessionRemote.reject(admin1, approvalId, rejection);
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_REJECTED, next.getStatus());
        assertEquals("No approvals expected to be required.", 0, next.getRemainingApprovals());

        // Try to approve a rejected request
        try {
            approvalExecutionSessionRemote.approve(admin2, approvalId, approval1);
            fail("It shouldn't be possible to approve a rejected request");
        } catch (ApprovalException e) {
            log.info("ApprovalException: " + e.getErrorCode() + ". " + e.getMessage());
        }

        // Test that the approval expires as it should
        Thread.sleep(1100);
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());

        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_EXPIRED, next.getStatus());

        // Try to reject an expired request
        try {
            approvalExecutionSessionRemote.reject(admin2, approvalId, rejection);
            fail("It shouln't be possible to reject and expired request");
        } catch (ApprovalException e) {
            log.debug("Caught expected exception: " + e.getMessage());
        }

        approvalSessionRemote.removeApprovalRequest(admin1, next.getId());

        log.trace("<testReject()");
    }

    @Test
    public void testIsApproved() throws Exception {
        log.trace(">testIsApproved");
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest);

        int status = approvalSessionRemote.isApproved(approvalId);
        assertEquals(2, status);

        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));

        status = approvalSessionRemote.isApproved(approvalId);
        assertEquals(1, status);

        approvalExecutionSessionRemote.approve(admin2, approvalId, createApproval("ap2test"));

        status = approvalSessionRemote.isApproved(approvalId);
        assertEquals(ApprovalDataVO.STATUS_APPROVED, status);
        log.trace("<testIsApproved");
    }

    @Test
    public void testExtendApprovalRequest() throws Exception {
        log.trace(">testExtendApprovalRequest");
        int approvalId = removeApprovalIds.get(0);
        int requestId = approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        Thread.sleep(1100);

        // Should be in expired state now
        ApprovalDataVO result = approvalSessionRemote.findNonExpiredApprovalRequest(approvalId);
        assertNull(result);

        // Try to extend without having enabled request extension in the profile. Should fail
        try {
            approvalSessionProxyRemote.extendApprovalRequestNoAuth(admin1, requestId, 1000);
            fail("Should not be able to extend request when disabled in profile");
        } catch (Exception e) {
            // NOPMD expected
        }

        // Enable approval extension
        approvalProfile.setMaxExtensionTime(3000);
        approvalProfileSession.changeApprovalProfile(intadmin, approvalProfile);

        // Extend the validity of the request
        approvalSessionProxyRemote.extendApprovalRequestNoAuth(admin1, requestId, 2000);

        // Should have been unexpired, so findNonExpiredApprovalRequest should return it.
        // And the approvalId (the request hash) should not change by a change of expiry date.
        log.debug("Trying to find approval with ApprovalId " + approvalId);
        result = approvalSessionRemote.findNonExpiredApprovalRequest(approvalId);
        assertNotNull(result);
        assertEquals(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, result.getStatus()); // should not change at all during the test, just a safety check
        log.trace("<testExtendApprovalRequest");
    }

    @Test
    public void testFindNonExpiredApprovalRequest() throws Exception {
        log.trace(">testFindNonExpiredApprovalRequest");
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        Thread.sleep(1100);
        // Then after one of them have expired
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);

        ApprovalDataVO result = approvalSessionRemote.findNonExpiredApprovalRequest(approvalId);
        assertNotNull("Approval should not be found, because it should have expired", result);
        assertEquals(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, result.getStatus());
        log.trace("<testFindNonExpiredApprovalRequest");
    }

    @Test
    public void testQuery() throws Exception {
        log.trace(">testQuery");
        // Add a few requests
        final DummyApprovalRequest req1 = new DummyApprovalRequest(reqadmin, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, false, approvalProfile);
        final int req1ApprovalId = req1.generateApprovalId();
        final DummyApprovalRequest req2 = new DummyApprovalRequest(admin1, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, false, approvalProfile);
        final int req2ApprovalId = req2.generateApprovalId();
        final DummyApprovalRequest req3 = new DummyApprovalRequest(admin2, null, 3, 2, false, approvalProfile);
        final int req3ApprovalId = req3.generateApprovalId();
        removeApprovalIds.add(req1ApprovalId);
        removeApprovalIds.add(req2ApprovalId);
        removeApprovalIds.add(req3ApprovalId);

        approvalSessionRemote.addApprovalRequest(admin1, req1);
        approvalSessionRemote.addApprovalRequest(admin1, req2);
        approvalSessionRemote.addApprovalRequest(admin1, req3);

        // Make some queries
        Query q1 = new Query(Query.TYPE_APPROVALQUERY);
        q1.add(ApprovalMatch.MATCH_WITH_APPROVALTYPE, BasicMatch.MATCH_TYPE_EQUALS, "" + req1.getApprovalType());

        List<ApprovalDataVO> result = approvalSessionProxyRemote.query(q1, 0, 3, "cAId=" + caid,
                "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 2 && result.size() <= 3);

        result = approvalSessionProxyRemote.query(q1, 1, 3, "cAId=" + caid, "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 1 && result.size() <= 3);

        result = approvalSessionProxyRemote.query(q1, 0, 1, "cAId=" + caid, "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
        assertEquals("Result size " + result.size(), 1, result.size());

        Query q2 = new Query(Query.TYPE_APPROVALQUERY);
        q2.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, "" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, Query.CONNECTOR_AND);
        q2.add(ApprovalMatch.MATCH_WITH_REQUESTADMINCERTSERIALNUMBER, BasicMatch.MATCH_TYPE_EQUALS, reqadmincert.getSerialNumber().toString(16));

        result = approvalSessionProxyRemote.query(q1, 1, 3, "cAId=" + caid, "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
        assertTrue("Result size " + result.size(), result.size() >= 1 && result.size() <= 3);

        log.trace("<testQuery");
    }

    @Test
    public void testExpiredQuery() throws Exception {
        log.trace(">testExpiredQuery");
        approvalProfile.setRequestExpirationPeriod(0);
        approvalProfileSession.changeApprovalProfile(intadmin, approvalProfile);
        // Add a few requests
        final DummyApprovalRequest expiredRequest = new DummyApprovalRequest(admin3, null, caid, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, false, approvalProfile);
        removeApprovalIds.add(expiredRequest.generateApprovalId());
        approvalSessionRemote.addApprovalRequest(admin1, expiredRequest);
        Query expiredQuery = new Query(Query.TYPE_APPROVALQUERY);
        expiredQuery.add(ApprovalMatch.MATCH_WITH_APPROVALTYPE, BasicMatch.MATCH_TYPE_EQUALS, "" + expiredRequest.getApprovalType(), Query.CONNECTOR_AND);
        expiredQuery.add(TimeMatch.MATCH_WITH_EXPIRETIME, null, new Date());
        List<ApprovalDataVO> result = approvalSessionProxyRemote.query(
                expiredQuery,
                0,
                3,
                "cAId=" + caid,
                "(endEntityProfileId=" + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + ")");
        assertTrue("At least one expired query was not returned.", result.size() > 0);
        log.trace("<testExpiredQuery");
    }

    @Test
    public void testGetRemainingNumberOfApprovals() throws Exception {
        int approvalId = removeApprovalIds.get(0);
        final int requestId = approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        assertEquals("There should be only one approval remaining", 1, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
        approvalExecutionSessionRemote.approve(admin2, approvalId, createApproval("ap2test"));
        assertEquals("There should be no approvals remaining", 0, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
    }

    @Test(expected = ApprovalException.class)
    public void shouldFailOnDuplicateApprovalRequests() throws ApprovalException {
        // given
        // when
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
    }

    @Test
    public void testGetRemainingNumberOfApprovalsOnExpiredRequest() throws Exception {
        int approvalId = removeApprovalIds.get(0);
        int requestId = approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        approvalExecutionSessionRemote.approve(admin2, approvalId, createApproval("ap2test"));
        // Make sure that the approval still have status executed after expiration
        Thread.sleep(1100);
        assertEquals("There should be no approvals remaining", 0, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
    }

    @Test(expected = ApprovalRequestExpiredException.class)
    public void shouldFailOnCallIsApprovedWhenApprovalRequestExpired() throws Exception {
        // given
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        approvalExecutionSessionRemote.approve(admin2, approvalId, createApproval("ap2test"));
        approvalSessionRemote.isApproved(approvalId);
        Thread.sleep(1100);
        // when
        approvalSessionRemote.isApproved(approvalId);
    }

    @Test
    public void shouldChangeTheStatusToExpiredNotifiedAfterApprovalRequestExpiredExceptionIsThrown() throws Exception {
        // given
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(reqadmin, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        approvalExecutionSessionRemote.approve(admin2, approvalId, createApproval("ap2test"));
        approvalSessionRemote.isApproved(approvalId);
        Thread.sleep(1100);
        // when
        try {
            approvalSessionRemote.isApproved(approvalId);
        } catch (ApprovalRequestExpiredException ignored) {
        }
        final int actualStatus = approvalSessionRemote.isApproved(approvalId);
        // status
        assertEquals(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED, actualStatus);
    }

    @Test(expected = AdminAlreadyApprovedRequestException.class)
    public void shouldFailOnDuplicateApprovalBySameAdmin() throws Exception {
        // given
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        // when
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("apAgaintest"));
    }

    @Test(expected = AdminAlreadyApprovedRequestException.class)
    public void shouldFailOnRequestAndApprovalByTheSameAdmin() throws Exception {
        // given
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        // when
        approvalExecutionSessionRemote.approve(reqadmin, approvalId, createApproval("approvalUsingReqAdmin"));
    }

    @Test
    public void testGetRemainingNumberOfApprovalsOnRejectedRequest() throws Exception {
        int approvalId = removeApprovalIds.get(0);
        int requestId = approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("testGetRemainingNumberOfApprovalsOnRejectedRequest1"));
        assertEquals("There should be only one approval remaining", 1, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
        approvalExecutionSessionRemote.reject(admin2, approvalId, createApproval("testGetRemainingNumberOfApprovalsOnRejectedRequest2"));
        assertEquals("Returned status should be -1", -1, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
    }

    @Test
    public void testGetRemainingNumberOfApprovalsOnRejectedAndExpiredRequest() throws Exception {
        int approvalId = removeApprovalIds.get(0);
        int requestId = approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);
        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("testGetRemainingNumberOfApprovalsOnRejectedAndExpiredRequest1"));
        approvalExecutionSessionRemote.reject(admin2, approvalId, createApproval("testGetRemainingNumberOfApprovalsOnRejectedAndExpiredRequest2"));
        // Make sure that the approval still have status rejected after expiration
        Thread.sleep(1100);
        approvalSessionRemote.getRemainingNumberOfApprovals(requestId);
        assertEquals("Returned status should be -1", -1, approvalSessionRemote.getRemainingNumberOfApprovals(requestId));
    }

    @Test
    public void testApprovalsWithExternalAdmins() throws Exception {
        log.trace(">testApprovalsWithExternalAdmins()");
        int approvalId = removeApprovalIds.get(0);
        approvalSessionRemote.addApprovalRequest(admin1, nonExecutableRequest);

        approvalExecutionSessionRemote.approve(admin1, approvalId, createApproval("ap1test"));
        Collection<ApprovalDataVO> result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());
        ApprovalDataVO next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, next.getStatus());
        assertEquals(1, next.getRemainingApprovals());

        approvalExecutionSessionRemote.approve(externaladmin, approvalId, createApproval("ap2test"));
        result = approvalSessionRemote.findApprovalDataVO(approvalId);
        assertEquals(1, result.size());
        next = result.iterator().next();
        assertEquals("Status = " + next.getStatus(), ApprovalDataVO.STATUS_APPROVED, next.getStatus());
        assertEquals(0, next.getRemainingApprovals());
        log.trace("<testApprovalsWithExternalAdmins()");
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    private int getPartitionId() {
        return approvalProfile.getStep(AccumulativeApprovalProfile.FIXED_STEP_ID).getPartitions().values().iterator().next().getPartitionIdentifier();
    }

    private AuthenticationSubject makeAuthenticationSubject(X509Certificate certificate) {
        Set<Principal> principals = new HashSet<>(Collections.singletonList((Principal) certificate.getSubjectX500Principal()));
        Set<X509Certificate> credentials = new HashSet<>(Collections.singletonList(certificate));
        return new AuthenticationSubject(principals, credentials);
    }

    private AuthenticationToken getCliAdmin() {
        final String username = EjbcaConfiguration.getCliDefaultUser();
        final String password = EjbcaConfiguration.getCliDefaultPassword();
        final Set<Principal> principals = new HashSet<>();
        principals.add(new UsernamePrincipal(username));

        final AuthenticationSubject subject = new AuthenticationSubject(principals, null);

        final CliAuthenticationToken authenticationToken = (CliAuthenticationToken) EjbRemoteHelper.INSTANCE.getRemoteSession(
                CliAuthenticationProviderSessionRemote.class).authenticate(subject);

        authenticationToken.setSha1HashFromCleartextPassword(password);
        return authenticationToken;

    }

    private Approval createApproval(final String approvalComment) {
        return new Approval(approvalComment, AccumulativeApprovalProfile.FIXED_STEP_ID, getPartitionId());
    }
}
