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
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
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
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * Handles execution of approved tasks. Separated from ApprovealSessionBean to avoid
 * circular dependencies, since execution will require SSBs that originally created the
 * approval request.
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalExecutionSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalExecutionSessionBean implements ApprovalExecutionSessionLocal, ApprovalExecutionSessionRemote {

	private static final Logger log = Logger.getLogger(ApprovalExecutionSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    @Override
    public void approve(AuthenticationToken admin, int approvalId, Approval approval) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, 
            ApprovalException, SelfApprovalException, AuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">approve: "+approvalId);
        }
        final ApprovalData approvalData = approvalSession.findNonExpiredApprovalDataLocal(approvalId);
        if (approvalData == null) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, msg);
        }
        assertAuthorizedToApprove(admin, approvalData);   
        checkApprovalPossibility(admin, approvalData, approval);
		approval.setApprovalAdmin(true, admin);
        try {
            ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalData.getApprovalRequest().getApprovalProfile().getProfileId());
            if(approvalProfile == null) {
                approvalProfile = approvalData.getApprovalDataVO().getApprovalRequest().getApprovalProfile();
            }
            final List<Approval> approvalsPerformed = approvalData.getApprovals();
            if (approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
                throw new ApprovalException("Wrong status of approval request, expected STATUS_WAITINGFORAPPROVAL(-1): "+approvalData.getStatus());
            }
            // Check if the approval is applicable, i.e belongs to and satisfies a certain partition, as well as that all previous steps have been satisfied
            if (!approvalProfile.isApprovalAuthorized(approvalsPerformed, approval)) {
                throw new AuthorizationDeniedException("Administrator " + approval.getAdmin().toString() + " was not authorized to partition " + approval.getPartitionId()
                                + " in step " + approval.getStepId() + " of approval profile " + approvalProfile.getProfileName());
            }
            approvalsPerformed.add(approval);
            if (approvalData.hasRequestOrApprovalExpired()) {
                approvalSession.sendApprovalNotifications(admin, approvalData.getApprovalRequest(), approvalProfile, approvalsPerformed, false);
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
                            ((AddEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
                            ((ChangeStatusEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
                            ((EditEndEntityApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
                            ((KeyRecoveryApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else if (approvalRequest instanceof RevocationApprovalRequest) {
                            ((RevocationApprovalRequest) approvalRequest).execute(endEntityManagementSession);
                        } else {
                            approvalRequest.execute();
                        }
                        approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTED);
                    } catch (ApprovalRequestExecutionException e) {
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
            approvalSession.sendApprovalNotifications(admin, approvalData.getApprovalRequest(), approvalProfile, approvalsPerformed, false);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.approved", approvalId));
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
        } catch (ApprovalRequestExpiredException e) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.expired", approvalId));
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
            throw e;
        } catch (ApprovalRequestExecutionException e) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("approval.errorexecuting", approvalId));
            details.put("error", e.getMessage());
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<approve: " + approvalId+", "+approvalData.getStatus());
        }
    }

    @Override
    public void reject(AuthenticationToken admin, int approvalId, Approval approval)
            throws ApprovalRequestExpiredException, AuthorizationDeniedException, ApprovalException, AdminAlreadyApprovedRequestException,
            SelfApprovalException, AuthenticationFailedException {
        log.trace(">reject");
        final ApprovalData approvalData = approvalSession.findNonExpiredApprovalDataLocal(approvalId);
        if (approvalData == null) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, msg);
        }
        assertAuthorizedToApprove(admin, approvalData);
        checkApprovalPossibility(admin, approvalData, approval);
        approval.setApprovalAdmin(false, admin);
        try {
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalData.getApprovalRequest().getApprovalProfile().getProfileId());
            final List<Approval> approvalsPerformed = approvalData.getApprovals();
            // Check if the approval is applicable, i.e belongs to and satisfies a certain partition, as well as that all previous steps have been satisfied
            if (!approvalProfile.isApprovalAuthorized(approvalsPerformed, approval)) {
                throw new AuthorizationDeniedException("Administrator " + approval.getAdmin().toString() + " was not authorized to partition " + approval.getPartitionId()
                                + " in step " + approval.getStepId() + " of approval profile " + approvalProfile.getProfileName());
            }
            approvalsPerformed.add(approval);
            if (approvalData.hasRequestOrApprovalExpired()) {
                approvalSession.sendApprovalNotifications(admin, approvalData.getApprovalRequest(), approvalProfile, approvalsPerformed, true);
                throw new ApprovalRequestExpiredException();
            }
            if (approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
                throw new ApprovalException("Wrong status of approval request.");
            }
            approvalSession.setApprovals(approvalData, approvalsPerformed);
            //Retrieve the approval profile just to make sure that the state is still valid
            approvalProfile.canApprovalExecute(approvalsPerformed);
            //Kept for legacy reasons
            approvalData.setRemainingapprovals(0);
            if (approvalData.getApprovalRequest().isExecutable()) {
                approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
                approvalData.setExpireDate(new Date());
            } else {
                approvalData.setStatus(ApprovalDataVO.STATUS_REJECTED);
                approvalData.setExpiredate((new Date()).getTime() + approvalData.getApprovalRequest().getApprovalValidity());
            }
            approvalSession.sendApprovalNotifications(admin, approvalData.getApprovalRequest(), approvalProfile, approvalsPerformed, false);
            final String detailsMsg = intres.getLocalizedMessage("approval.rejected", approvalId);
            auditSession.log(EjbcaEventTypes.APPROVAL_REJECT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalData.getCaid()), null, null, detailsMsg);
        } catch (ApprovalRequestExpiredException e) {
            log.info(intres.getLocalizedMessage("approval.expired", approvalId));
            throw e;
        }
        log.trace("<reject");
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
        if (approvalInformation.getApprovalRequest().isEditedByMe(admin)) {
            throw new SelfApprovalException("Can't approve a request that was last edited by oneself");
        }
       

    }
    
    /**
     * Asserts general authorization to approve 
     * @throws AuthorizationDeniedException if any authorization error occurred  
     */
    private void assertAuthorizedToApprove(AuthenticationToken admin, final ApprovalData approvalData) throws AuthorizationDeniedException {
        if (approvalData.getEndentityprofileid() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
            if (!accessControlSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_APPROVECAACTION,
                        null);
                throw new AuthorizationDeniedException(msg);
            }
        } else {
            if (!accessControlSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY)) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_APPROVEENDENTITY,
                        null);
                throw new AuthorizationDeniedException(msg);
            }
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
                if (!accessControlSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + approvalData.getEndentityprofileid()
                        + AccessRulesConstants.APPROVE_END_ENTITY)) {
                    final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ENDENTITYPROFILEPREFIX
                            + approvalData.getEndentityprofileid() + AccessRulesConstants.APPROVE_END_ENTITY, null);
                    throw new AuthorizationDeniedException(msg);
                }
            }
        }
        if (approvalData.getCaid() != ApprovalDataVO.ANY_CA) {
            if (!accessControlSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + approvalData.getCaid())) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                        StandardRules.CAACCESS.resource() + approvalData.getCaid(), null);
                throw new AuthorizationDeniedException(msg);
            }
        }

    }
}
