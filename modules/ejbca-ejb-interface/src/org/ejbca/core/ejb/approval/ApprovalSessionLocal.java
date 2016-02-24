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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.SelfApprovalException;

/**
 * Local interface for ApprovalSession.
 */
@Local
public interface ApprovalSessionLocal extends ApprovalSession {

    /**
     * Method used to reject an approval requests.
     * 
     * It does the following 1. checks if the approval with the status waiting
     * exists, throws an ApprovalRequestDoesntExistException otherwise
     * 
     * 2. check if the administrator is authorized using the follwing rules: 2.1
     * if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     * authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise
     * AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     * end entity profile. 2.2 Checks if the admin is authoried to the approval
     * requests getCAId()
     * 
     * 3. looks upp the username of the administrator and checks that no
     * approval have been made by this user earlier.
     * 
     * 4. Runs the approval command in the end entity bean.
     * 
     * @param gc is the GlobalConfiguration used for notification info
     */
	ApprovalData isAuthorizedBeforeApproveOrReject(AuthenticationToken admin, int approvalId) throws ApprovalException, AuthorizationDeniedException;

    /** Verifies that an administrator can approve an action, i.e. that it is not the same admin approving the request as made the request originally.
     * An admin is not allowed to approve his/her own actions.
     * 
     * @param admin the administrator that tries to approve the action
     * @param adl the action that the administrator tries to approve
     * @throws AdminAlreadyApprovedRequestException if the admin has already approved the action before
     * @throws SelfApprovalException if the administrator performing the approval is the same as the one requesting the original action. 
     */
	void checkExecutionPossibility(AuthenticationToken admin, ApprovalData adl) throws AdminAlreadyApprovedRequestException, SelfApprovalException;

	/** Method that returns the approval data value object. */
	ApprovalDataVO getApprovalDataVO(ApprovalData adl);

	void sendApprovalNotification(AuthenticationToken admin, String approvalAdminsEmail, String approvalNotificationFromAddress, String approvalURL,
            String notificationSubject, String notificationMsg, Integer id, int numberOfApprovalsLeft, Date requestDate, ApprovalRequest approvalRequest,
            Approval approval);

	Collection<Approval> getApprovals(ApprovalData approvalData);

	/**
	 * Encode a Collection of Approval and set it in ApprovalData object.
	 * @param approvals cannot be null.
	 */
	void setApprovals(ApprovalData approvalData, Collection<Approval> approvals);

	ApprovalRequest getApprovalRequest(ApprovalData approvalData);
}
