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

import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
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
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;

/**
 * Handles execution of approved tasks. Separated from ApprovealSessionBean to avoid
 * circular dependencies, since execution will require SSBs that originally created the
 * approval request.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalExecutionSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalExecutionSessionBean implements ApprovalExecutionSessionLocal, ApprovalExecutionSessionRemote {

	static final Logger log = Logger.getLogger(ApprovalExecutionSessionBean.class);
    static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Override
    public void approve(AuthenticationToken admin, int approvalId, Approval approval, ApprovalStep approvalStep, 
            final boolean isNrOfApprovalsProfile) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, ApprovalException, SelfApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">approve: "+approvalId);
        }
        ApprovalData adl;
        try {
            adl = approvalSession.isAuthorizedBeforeApproveOrReject(admin, approvalId, approvalStep);
        } catch (ApprovalException e) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);            	
        	log.info(msg, e);
            throw e;
        }
        approvalSession.checkExecutionPossibility(admin, adl, approvalStep);
		approval.setApprovalAdmin(true, admin);
        try {
            approve(adl, approval, approvalStep, isNrOfApprovalsProfile);
            GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (gc.getUseApprovalNotifications()) {
            	final ApprovalDataVO approvalDataVO = approvalSession.getApprovalDataVO(adl);
                if (approvalDataVO.getRemainingApprovals() != 0) {
                	approvalSession.sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                            + "adminweb/approval/approveaction.jsf?uniqueId=" + adl.getId(),
                            intres.getLocalizedMessage("notification.requestconcured.subject"), intres.getLocalizedMessage("notification.requestconcured.msg"),
                            adl.getId(), approvalDataVO.getRemainingApprovals(), approvalDataVO.getRequestDate(), approvalDataVO.getApprovalRequest(), approval);
                } else {
                	approvalSession.sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                            + "adminweb/approval/approveaction.jsf?uniqueId=" + adl.getId(),
                            intres.getLocalizedMessage("notification.requestapproved.subject"), intres.getLocalizedMessage("notification.requestapproved.msg"),
                            adl.getId(), approvalDataVO.getRemainingApprovals(), approvalDataVO.getRequestDate(), approvalDataVO.getApprovalRequest(), approval);
                }
            }
            String msg = intres.getLocalizedMessage("approval.approved", approvalId);            	
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(adl.getCaid()), null, null, details);
        } catch (ApprovalRequestExpiredException e) {
            String msg = intres.getLocalizedMessage("approval.expired", approvalId);            	
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(adl.getCaid()), null, null, details);
            throw e;
        } catch (ApprovalRequestExecutionException e) {
            String msg = intres.getLocalizedMessage("approval.errorexecuting", approvalId);            	
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("error", e.getMessage());
            auditSession.log(EjbcaEventTypes.APPROVAL_APPROVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(adl.getCaid()), null, null, details);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace(">approve: "+approvalId);
        }
    }

	/**
	 * Method adds an approval to the approval data.
	 * If the number of required approvals have been reached will
	 * the request be executed and expiredate set.
	 * 
	 * @throws ApprovalRequestExpiredException 
	 * @throws ApprovalRequestExecutionException 
	 * @throws ApprovalException 
	 */
	private void approve(final ApprovalData approvalData, final Approval approval, final ApprovalStep approvalStep, 
	        final boolean isNrOfApprovalProfile) throws ApprovalRequestExpiredException, ApprovalRequestExecutionException, ApprovalException {
	    
		if(approvalData.hasRequestOrApprovalExpired()){
			throw new ApprovalRequestExpiredException();
		}
		if(approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			throw new ApprovalException("Wrong status of approval request.");
		}
		
		boolean readyToCheckExecution = false;
		if(isNrOfApprovalProfile) {
		    final int numberofapprovalsleft = approvalData.getRemainingapprovals() -1;
		    if(numberofapprovalsleft < 0){
		        throw new ApprovalException("Error already enough approvals have been done on this request.");
		    }
		    approvalData.setRemainingapprovals(numberofapprovalsleft);
		     
		    final Collection<Approval> approvals = approvalSession.getApprovals(approvalData);
		    approvals.add(approval);
		    approvalSession.setApprovals(approvalData, approvals);

		    readyToCheckExecution = numberofapprovalsleft == 0;
		} else {
		    approvalSession.addApprovalToApprovalStep(approvalData, approval, approvalStep);
		    final ApprovalRequest approvalRequest = approvalSession.getApprovalRequest(approvalData);
		    readyToCheckExecution = approvalRequest.getNextUnhandledAppprovalStep() == null;
		}
		
		if(readyToCheckExecution){
			final ApprovalRequest approvalRequest = approvalSession.getApprovalRequest(approvalData);
			if(approvalRequest.isExecutable()){
				try{
					if (approvalRequest instanceof ActivateCATokenApprovalRequest) {
						((ActivateCATokenApprovalRequest)approvalRequest).execute(caAdminSession);
					} else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
						((AddEndEntityApprovalRequest)approvalRequest).execute(endEntityManagementSession);
					} else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
						((ChangeStatusEndEntityApprovalRequest)approvalRequest).execute(endEntityManagementSession);
					} else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
						((EditEndEntityApprovalRequest)approvalRequest).execute(endEntityManagementSession);
					} else if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
						((KeyRecoveryApprovalRequest)approvalRequest).execute(endEntityManagementSession);
					} else if (approvalRequest instanceof RevocationApprovalRequest) {
						((RevocationApprovalRequest)approvalRequest).execute(endEntityManagementSession);
					} else {
						approvalRequest.execute();
					}
					approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTED);
				} catch(ApprovalRequestExecutionException e){
					approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONFAILED);
					throw e;
				}
				approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTED);
				approvalData.setExpireDate(new Date());
			}else{
				approvalData.setStatus(ApprovalDataVO.STATUS_APPROVED);
				approvalData.setExpiredate((new Date()).getTime() + approvalRequest.getApprovalValidity());
			}
		}
	}
}
