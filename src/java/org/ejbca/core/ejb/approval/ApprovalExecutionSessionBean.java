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

import java.util.Collection;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.log.LogConstants;

/**
 * Handles execution of approved tasks. Separated from ApprovealSessionBean to avoid
 * circular dependencies, since execution will require SSBs that originally created the
 * approval request.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ApprovalExecutionSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalExecutionSessionBean implements ApprovalExecutionSessionLocal, ApprovalExecutionSessionRemote {

	static final Logger log = Logger.getLogger(ApprovalExecutionSessionBean.class);
    static final InternalResources intres = InternalResources.getInstance();

    @EJB UserAdminSessionLocal userAdminSession;
    @EJB CAAdminSessionLocal caAdminSession;
    @EJB ApprovalSessionLocal approvalSession;
    @EJB LogSessionLocal logSession;

    @Override
    public void approve(AuthenticationToken admin, int approvalId, Approval approval, GlobalConfiguration gc) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, EjbcaException {
        log.trace(">approve");
        ApprovalData adl;
        try {
            adl = approvalSession.isAuthorizedBeforeApproveOrReject(admin, approvalId);
        } catch (ApprovalException e) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALAPPROVED,
                    "Approval request with id : " + approvalId + " doesn't exists.");
            throw e;
        }
        approvalSession.checkExecutionPossibility(admin, adl);
		approval.setApprovalAdmin(true, admin);
        try {
            approve(adl, approval);
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
            logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_INFO_APPROVALAPPROVED,
                    "Approval request with id : " + approvalId + " have been approved.");
        } catch (ApprovalRequestExpiredException e) {
            logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALAPPROVED,
                    "Approval request with id : " + approvalId + " have expired.");
            throw e;
        } catch (ApprovalRequestExecutionException e) {
            logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALAPPROVED,
                    "Approval with id : " + approvalId + " couldn't execute properly");
            throw e;
        }
        log.trace("<approve");
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
	private void approve(final ApprovalData approvalData, final Approval approval) throws ApprovalRequestExpiredException, ApprovalRequestExecutionException, ApprovalException {
		if(approvalData.haveRequestOrApprovalExpired()){
			throw new ApprovalRequestExpiredException();
		}
		if(approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			throw new ApprovalException("Wrong status of approval request.");
		}
		final int numberofapprovalsleft = approvalData.getRemainingapprovals() -1;
		if(numberofapprovalsleft < 0){
			throw new ApprovalException("Error already enough approvals have been done on this request.");
		}
		approvalData.setRemainingapprovals(numberofapprovalsleft);
		final Collection<Approval> approvals = approvalSession.getApprovals(approvalData);
		approvals.add(approval);
		approvalSession.setApprovals(approvalData, approvals);
		if(numberofapprovalsleft == 0){
			final ApprovalRequest approvalRequest = approvalSession.getApprovalRequest(approvalData);
			if(approvalRequest.isExecutable()){
				try{
					if (approvalRequest instanceof ActivateCATokenApprovalRequest) {
						((ActivateCATokenApprovalRequest)approvalRequest).execute(caAdminSession);
					} else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
						((AddEndEntityApprovalRequest)approvalRequest).execute(userAdminSession);
					} else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
						((ChangeStatusEndEntityApprovalRequest)approvalRequest).execute(userAdminSession);
					} else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
						((EditEndEntityApprovalRequest)approvalRequest).execute(userAdminSession);
					} else if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
						((KeyRecoveryApprovalRequest)approvalRequest).execute(userAdminSession);
					} else if (approvalRequest instanceof RevocationApprovalRequest) {
						((RevocationApprovalRequest)approvalRequest).execute(userAdminSession);
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
