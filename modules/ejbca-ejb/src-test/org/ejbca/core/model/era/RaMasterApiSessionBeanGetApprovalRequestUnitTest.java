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
package org.ejbca.core.model.era;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.LogRedactionConfigurationCache;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.roles.management.RoleSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.test.EjbMocker;
import org.ejbca.util.query.IllegalQueryException;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the view_approvals access rule check in {@link RaMasterApiSessionBean#getApprovalRequest(AuthenticationToken, int)}.
 */
public class RaMasterApiSessionBeanGetApprovalRequestUnitTest {

    private static final int APPROVAL_ID = 42;
    private static final int CA_ID = 100;
    private static final int EEP_ID = 200;

    private RaMasterApiSessionBean raMasterApi;

    private ApprovalSessionLocal approvalSessionMock;
    private AuthorizationSessionLocal authorizationSessionMock;
    private CaSessionLocal caSessionMock;
    private CertificateProfileSessionLocal certificateProfileSessionMock;
    private EndEntityProfileSessionLocal endEntityProfileSessionMock;
    private RoleSessionLocal roleSessionMock;

    private AuthenticationToken admin;
    private ApprovalDataVO approvalDataVO;
    private ApprovalRequest approvalRequest;
    private CAInfo caInfo;
    private ApprovalProfile approvalProfileMock;

    @Before
    public void before() throws Exception {
        approvalSessionMock = EasyMock.createNiceMock(ApprovalSessionLocal.class);
        authorizationSessionMock = EasyMock.createNiceMock(AuthorizationSessionLocal.class);
        caSessionMock = EasyMock.createNiceMock(CaSessionLocal.class);
        certificateProfileSessionMock = EasyMock.createNiceMock(CertificateProfileSessionLocal.class);
        endEntityProfileSessionMock = EasyMock.createNiceMock(EndEntityProfileSessionLocal.class);
        roleSessionMock = EasyMock.createNiceMock(RoleSessionLocal.class);

        admin = createAdminToken("admin");
        caInfo = new X509CAInfo.X509CAInfoBuilder().setSubjectDn("CN=TestCA").build();
        caInfo.setName("TestCA");
        caInfo.setCAId(CA_ID);

        approvalProfileMock = EasyMock.createNiceMock(ApprovalProfile.class);

        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionCache(Collections.emptyMap(), Collections.emptyMap());

        final EjbMocker<RaMasterApiSessionBean> mocker = new EjbMocker<>(RaMasterApiSessionBean.class);
        mocker.addMockedInjections(approvalSessionMock, authorizationSessionMock, caSessionMock,
                certificateProfileSessionMock, endEntityProfileSessionMock, roleSessionMock);
        raMasterApi = mocker.construct();
    }

    private AuthenticationToken createAdminToken(final String name) throws Exception {
        final X509Certificate certMock = EasyMock.createNiceMock(X509Certificate.class);
        expect(certMock.getSubjectX500Principal()).andReturn(new X500Principal("CN=" + name)).anyTimes();
        expect(certMock.getEncoded()).andReturn(new byte[]{1, 2, 3}).anyTimes();
        replay(certMock);
        return new X509CertificateAuthenticationToken(certMock);
    }

    /**
     * Sets up common expectations for the approval data query and CA access check.
     * The approval request has a different creator than the admin under test.
     */
    private void expectApprovalDataLookupAndCaCheck(final AuthenticationToken creator) throws IllegalQueryException, AuthorizationDeniedException {
        approvalRequest = new AddEndEntityApprovalRequest(new EndEntityInformation(), false, creator, null, CA_ID, EEP_ID, approvalProfileMock, null);
        approvalDataVO = new ApprovalDataVO(APPROVAL_ID, 1, 1, EEP_ID, CA_ID, "issuer", "sn", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                Collections.emptyList(), approvalRequest, new Date(), new Date());

        final List<ApprovalDataVO> approvalList = new ArrayList<>();
        approvalList.add(approvalDataVO);
        expect(approvalSessionMock.query(anyObject(), eq(0), eq(100), eq(""), eq(""))).andReturn(approvalList);
        expect(caSessionMock.getCAInfo(admin, CA_ID)).andReturn(caInfo);
    }

    /**
     * Sets up expectations for the remainder of getApprovalRequest after the view_approvals check passes.
     */
    private void expectApprovalRequestBuildingCalls() {
        expect(endEntityProfileSessionMock.getEndEntityProfileName(EEP_ID)).andReturn("TestEEP");
        expect(endEntityProfileSessionMock.getEndEntityProfile(EEP_ID)).andReturn(EasyMock.createNiceMock(EndEntityProfile.class));
        expect(roleSessionMock.getRolesAuthenticationTokenIsMemberOf(admin)).andReturn(new ArrayList<RoleDataDto>());
    }

    /**
     * Given an admin without view_approvals who is not the creator of the request,
     * when getApprovalRequest is called, then null is returned (access denied).
     */
    @Test
    public void getApprovalRequestDeniedWhenNoViewApprovalsAndNotCreator() throws Exception {
        final AuthenticationToken otherAdmin = createAdminToken("otherAdmin");
        expectApprovalDataLookupAndCaCheck(otherAdmin);
        expect(authorizationSessionMock.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWAPPROVALS)).andReturn(false);
        replay(approvalSessionMock, authorizationSessionMock, caSessionMock, certificateProfileSessionMock,
                endEntityProfileSessionMock, roleSessionMock, approvalProfileMock);

        final RaApprovalRequestInfo result = raMasterApi.getApprovalRequest(admin, APPROVAL_ID);

        assertNull("Expected null when admin lacks view_approvals and is not the request creator", result);
    }

    /**
     * Given an admin with view_approvals who is not the creator of the request,
     * when getApprovalRequest is called, then the approval request info is returned.
     */
    @Test
    public void getApprovalRequestAllowedWhenHasViewApprovals() throws Exception {
        final AuthenticationToken otherAdmin = createAdminToken("otherAdmin");
        expectApprovalDataLookupAndCaCheck(otherAdmin);
        expect(authorizationSessionMock.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWAPPROVALS)).andReturn(true);
        expectApprovalRequestBuildingCalls();
        replay(approvalSessionMock, authorizationSessionMock, caSessionMock, certificateProfileSessionMock,
                endEntityProfileSessionMock, roleSessionMock, approvalProfileMock);

        final RaApprovalRequestInfo result = raMasterApi.getApprovalRequest(admin, APPROVAL_ID);

        assertNotNull("Expected non-null result when admin has view_approvals", result);
    }

    /**
     * Given an admin without view_approvals who IS the creator of the request,
     * when getApprovalRequest is called, then the approval request info is returned (creator exception).
     */
    @Test
    public void getApprovalRequestAllowedWhenCreatorEvenWithoutViewApprovals() throws Exception {
        // The creator is the same admin token
        expectApprovalDataLookupAndCaCheck(admin);
        expectApprovalRequestBuildingCalls();
        replay(approvalSessionMock, authorizationSessionMock, caSessionMock, certificateProfileSessionMock,
                endEntityProfileSessionMock, roleSessionMock, approvalProfileMock);

        final RaApprovalRequestInfo result = raMasterApi.getApprovalRequest(admin, APPROVAL_ID);

        assertNotNull("Expected non-null result when admin is the creator of the request", result);
    }
}
