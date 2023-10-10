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

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.authorization.AccessRulesConstants;

import com.keyfactor.ErrorCode;
import org.ejbca.util.approval.ApprovalUtil;

/**
 * Handles execution of approved tasks. Separated from ApprovealSessionBean to avoid
 * circular dependencies, since execution will require SSBs that originally created the
 * approval request.
 */
@SuppressWarnings("deprecation")
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalExecutionSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalExecutionSessionBean implements ApprovalExecutionSessionLocal, ApprovalExecutionSessionRemote {

	private static final Logger log = Logger.getLogger(ApprovalExecutionSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    @Override
    public void approve(AuthenticationToken admin, int approvalId, Approval approval) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, 
            ApprovalException, SelfApprovalException, AuthenticationFailedException, EndEntityExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">approve: hash="+approvalId);
        }
        final ApprovalData approvalData = approvalSession.findNonExpiredApprovalDataLocal(approvalId);
        if (approvalData == null) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, msg);
        }
        assertAuthorizedToApprove(admin, approvalData.getApprovalDataVO());   
        checkApprovalPossibility(admin, approvalData, approval);
		approval.setApprovalAdmin(true, admin);
        try {
            //Retrieve the latest non-stale version of the approval profile from the approval request (as the copy of the profile stored in the request may 
            //contain metadata which was added during the approval process. 
            final Integer approvalProfileId = approvalData.getApprovalRequest().getApprovalProfile().getProfileId();
            ApprovalProfile approvalProfile = null;
            if(approvalProfileId != null) {
                approvalProfile = approvalProfileSession.getApprovalProfile(approvalData.getApprovalRequest().getApprovalProfile().getProfileId().intValue());
            } else {
                approvalProfile = approvalData.getApprovalDataVO().getApprovalRequest().getApprovalProfile();
            }
            final List<Approval> approvalsPerformed = approvalData.getApprovals();
            if (approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
                throw new ApprovalException("Wrong status of approval request, expected STATUS_WAITINGFORAPPROVAL(-1): "+approvalData.getStatus());
            }
            final List<Role> rolesWhichApprovalAuthTokenIsMemberOf = roleSession.getRolesAuthenticationTokenIsMemberOf(approval.getAdmin());
            // Check if the approval is applicable, i.e belongs to and satisfies a certain partition, as well as that all previous steps have been satisfied
            if (!approvalProfile.isApprovalAuthorized(approvalsPerformed, approval, rolesWhichApprovalAuthTokenIsMemberOf)) {
                throw new AuthorizationDeniedException("Administrator " + approval.getAdmin().toString() + " was not authorized to partition " + approval.getPartitionId()
                                + " in step " + approval.getStepId() + " of approval profile " + approvalProfile.getProfileName());
            }
            approvalsPerformed.add(approval);
            if (approvalData.hasRequestOrApprovalExpired()) {
                approvalSession.sendApprovalNotifications(approvalData.getApprovalRequest(), approvalProfile, approvalData, false);
                throw new ApprovalRequestExpiredException();
            }
            final boolean readyToCheckExecution = approvalProfile.canApprovalExecute(approvalsPerformed);
            approvalSession.setApprovals(approvalData, approvalsPerformed);
            if (readyToCheckExecution) {
                //Kept for legacy reasons to allow for 100% uptime, can be removed once upgrading from 6.6.0 is no longer supported. 
                approvalData.setRemainingapprovals(0);
                final ApprovalRequest approvalRequest = approvalData.getApprovalRequest();
                if (approvalRequest.isExecutable()) {
                    try {
                        if (approvalRequest instanceof ActivateCATokenApprovalRequest) {
                            ((ActivateCATokenApprovalRequest) approvalRequest).execute(caAdminSession);
                        } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
                            ((AddEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession, 
                                    approvalSession.getIdFromApprovalId(approvalId), admin);
                        } else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
                            ((ChangeStatusEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession, 
                                    approvalSession.getIdFromApprovalId(approvalId), admin);
                        } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
                            ((EditEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession, 
                                    approvalSession.getIdFromApprovalId(approvalId), admin);
                        } else if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
                            ((KeyRecoveryApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else if (approvalRequest instanceof RevocationApprovalRequest) {
                            ((RevocationApprovalRequest) approvalRequest).execute(endEntityManagementSession, 
                                    approvalSession.getIdFromApprovalId(approvalId), admin);
                        } else {
                            approvalRequest.execute();
                        }
                        approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTED);
                    } catch (ApprovalRequestExecutionException | EndEntityExistsException e) {
                        approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONFAILED);
                        throw e;
                    }
                    approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTED);
                    approvalData.setExpireDate(new Date());
                } else {
                    approvalData.setStatus(ApprovalDataVO.STATUS_APPROVED);
                    approvalData.setExpiredate((new Date()).getTime() + approvalRequest.getApprovalValidity());
                }
            }
            // Notify all administrators affected by the work flow update
            approvalSession.sendApprovalNotifications(approvalData.getApprovalRequest(), approvalProfile, approvalData, false);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.approved", approvalData.getId()));

            List<ApprovalDataText> texts = approvalData.getApprovalRequest().getNewRequestDataAsText(admin);
            details = ApprovalUtil.updateWithApprovalDataText(details, texts);

            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
        } catch (ApprovalRequestExpiredException e) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.expired", approvalData.getId()));
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
            throw e;
        } catch (ApprovalRequestExecutionException e) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.errorexecuting", approvalData.getId()));
            details.put("error", LogRedactionUtils.getRedactedMessage(e.getMessage()));

            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
            throw e;
        } catch (EndEntityExistsException e) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.duplicateusername", approvalData.getId()));
            details.put("error", LogRedactionUtils.getRedactedMessage(e.getMessage()));

            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<approve: hash=" + approvalId+", id="+approvalData.getId()+", "+approvalData.getStatus());
        }
    }

    @Override
    public void reject(AuthenticationToken admin, int approvalId, Approval approval)
            throws ApprovalRequestExpiredException, AuthorizationDeniedException, ApprovalException, AdminAlreadyApprovedRequestException,
            SelfApprovalException, AuthenticationFailedException {
        log.trace(">reject: hash="+approvalId);
        final ApprovalData approvalData = approvalSession.findNonExpiredApprovalDataLocal(approvalId);
        if (approvalData == null) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, msg);
        }
        assertAuthorizedToApprove(admin, approvalData.getApprovalDataVO());
        checkApprovalPossibility(admin, approvalData, approval);
        approval.setApprovalAdmin(false, admin);
        try {
            //Retrieve the latest non-stale version of the approval profile from the approval request (as the copy of the profile stored in the request may 
            //contain metadata which was added during the approval process. 
            ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalData.getApprovalRequest().getApprovalProfile().getProfileId());
            if(approvalProfile == null) {
                approvalProfile = approvalData.getApprovalDataVO().getApprovalRequest().getApprovalProfile();
            }
            final List<Approval> approvalsPerformed = approvalData.getApprovals();
            final List<Role> rolesWhichApprovalAuthTokenIsMemberOf = roleSession.getRolesAuthenticationTokenIsMemberOf(approval.getAdmin());
            // Check if the approval is applicable, i.e belongs to and satisfies a certain partition, as well as that all previous steps have been satisfied
            if (!approvalProfile.isApprovalAuthorized(approvalsPerformed, approval, rolesWhichApprovalAuthTokenIsMemberOf)) {
                throw new AuthorizationDeniedException("Administrator " + approval.getAdmin().toString() + " was not authorized to partition " + approval.getPartitionId()
                                + " in step " + approval.getStepId() + " of approval profile " + approvalProfile.getProfileName());
            }
            approvalsPerformed.add(approval);
            if (approvalData.hasRequestOrApprovalExpired()) {
                approvalSession.sendApprovalNotifications(approvalData.getApprovalRequest(), approvalProfile, approvalData, true);
                throw new ApprovalRequestExpiredException();
            }
            if (approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
                throw new ApprovalException("Wrong status of approval request.");
            }
            approvalSession.setApprovals(approvalData, approvalsPerformed);
            //Retrieve the approval profile just to make sure that the state is still valid
            //Kept for legacy reasons
            approvalData.setRemainingapprovals(0);
            if (approvalData.getApprovalRequest().isExecutable()) {
                approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
                approvalData.setExpireDate(new Date());
            } else {
                approvalData.setStatus(ApprovalDataVO.STATUS_REJECTED);
                approvalData.setExpiredate((new Date()).getTime() + approvalData.getApprovalRequest().getApprovalValidity());
            }
            approvalSession.sendApprovalNotifications(approvalData.getApprovalRequest(), approvalProfile, approvalData, false);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.rejected", approvalData.getId()));

            List<ApprovalDataText> texts = approvalData.getApprovalRequest().getNewRequestDataAsText(admin);
            details = ApprovalUtil.updateWithApprovalDataText(details, texts);

            auditSession.log(EjbcaEventTypes.APPROVAL_REJECT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
        } catch (ApprovalRequestExpiredException e) {
            log.info(intres.getLocalizedMessage("approval.expired", approvalData.getId()));
            throw e;
        }
        log.trace("<reject: hash="+approvalId+", id="+approvalData.getId());
    }

	
    /** Verifies that an administrator can approve an action, i.e. that it is not the same admin approving the request as made the request originally.
     * An admin is not allowed to approve his/her own actions.
     * 
     * @param admin the administrator that tries to approve the action
     * @param approvalData the action that the administrator tries to approve
     * @param approval the new approval to vet
     * 
     * @throws AdminAlreadyApprovedRequestException if the admin has already approved the action before
     * @throws SelfApprovalException if the administrator performing the approval is the same as the one requesting the original action. 
     */
    private void checkApprovalPossibility(AuthenticationToken admin, ApprovalData approvalData, Approval approval)
            throws AdminAlreadyApprovedRequestException, SelfApprovalException {
        // Check that the approver's principals don't exist among the existing usernames.
        final ApprovalDataVO approvalInformation = approvalData.getApprovalDataVO();
        final int approvalId = approvalInformation.getApprovalId();
        if (approvalInformation.getReqadmincertissuerdn() != null) {
            // Check that the approver isn't the same as requested the action.
            AuthenticationToken requester = approvalData.getApprovalRequest().getRequestAdmin();
            if (admin.equals(requester)) {
                String msg = intres.getLocalizedMessage("approval.error.cannotapproveownrequest", approvalId);
                log.info(msg);
                throw new AdminAlreadyApprovedRequestException(msg);
            }
        }
        // Check that his admin has not approved this partition before
        for (Approval existingApproval : approvalInformation.getApprovals()) {
            if (existingApproval.getStepId() == approval.getStepId() 
                    && existingApproval.getPartitionId() == approval.getPartitionId()
                    && existingApproval.getAdmin().equals(admin)) {
                String msg = intres.getLocalizedMessage("approval.error.alreadyapproved", approvalId);
                log.info(msg);
                throw new AdminAlreadyApprovedRequestException(msg);
            }
        }
        // Check that the admin wasn't the last one who edited the request
        if (approvalInformation.getApprovalRequest().isEditedByMe(admin) && !approvalData.getApprovalDataVO().getApprovalProfile().getAllowSelfEdit()) {
            throw new SelfApprovalException("Can not approve a request that was last edited by oneself");
        }
    }
    
    @Override
    public void assertAuthorizedToApprove(AuthenticationToken admin, final ApprovalDataVO approvalData) throws AuthorizationDeniedException {
        if (approvalData.getEndEntityProfileId() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
            if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.REGULAR_APPROVECAACTION,
                        null);
                throw new AuthorizationDeniedException(msg);
            }
        } else {
            if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY)) {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.REGULAR_APPROVEENDENTITY,
                        null);
                throw new AuthorizationDeniedException(msg);
            }
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
                if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + approvalData.getEndEntityProfileId()
                        + AccessRulesConstants.APPROVE_END_ENTITY)) {
                    final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.ENDENTITYPROFILEPREFIX
                            + approvalData.getEndEntityProfileId() + AccessRulesConstants.APPROVE_END_ENTITY, null);
                    throw new AuthorizationDeniedException(msg);
                }
            }
        }
        if (approvalData.getCAId() != ApprovalDataVO.ANY_CA) {
            if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + approvalData.getCAId())) {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource",
                        StandardRules.CAACCESS.resource() + approvalData.getCAId(), null);
                throw new AuthorizationDeniedException(msg);
            }
        }
        
        // Check that the admin is allowed in the approval profile
        boolean allowed = false;
        final ApprovalStep nextStep;
        final ApprovalProfile approvalProfile = approvalData.getApprovalProfile();

        try {
            nextStep = approvalProfile.getStepBeingEvaluated(approvalData.getApprovals());
        } catch (AuthenticationFailedException e) {
            throw new IllegalStateException(e);
        }
        
        if (nextStep != null) {
            final Map<Integer, ApprovalPartition> partitions = nextStep.getPartitions();
            List<Role> roles = roleSession.getRolesAuthenticationTokenIsMemberOf(admin);
            for (ApprovalPartition partition : partitions.values()) {
                if (approvalProfile.canApprove(roles, partition)) {
                    allowed = true;
                    break;
                }
            }
        }
        if (!allowed) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoapprovalrequest",
                    admin, approvalData.getApprovalId(), approvalProfile.getProfileId());
            throw new AuthorizationDeniedException(msg);
        }

    }
}
