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
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalRequest;

/**
 * Local interface for ApprovalSession.
 */
@Local
public interface ApprovalSessionLocal extends ApprovalSession {

	void sendApprovalNotification(AuthenticationToken admin, String approvalAdminsEmail, String approvalNotificationFromAddress, String approvalURL,
            String notificationSubject, String notificationMsg, Integer id, int numberOfApprovalsLeft, Date requestDate, ApprovalRequest approvalRequest,
            Approval approval);

	/**
	 * Encode a Collection of Approval and set it in ApprovalData object.
	 * @param approvals cannot be null.
	 */
	void setApprovals(ApprovalData approvalData, Collection<Approval> approvals);
	
	 ApprovalData findNonExpiredApprovalDataLocal(int approvalId);

}
