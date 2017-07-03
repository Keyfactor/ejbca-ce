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
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Local interface for ApprovalSession.
 * 
 * @version $Id$
 */
@Local
public interface ApprovalSessionLocal extends ApprovalSession {

    /**
     * Send all work-flow related approval notifications given the last added Approval to the approvalsPerformed.
     * 
     * @param approvalRequest the approval request
     * @param approvalProfile the profile determining the approval work flow
     * @param approvalsPerformed a list of completed approvals so far with the current approval last
     * @param expired should be set to true if the notification is due to expiration of the approval request
     */
    void sendApprovalNotifications(ApprovalRequest approvalRequest, ApprovalProfile approvalProfile,
            ApprovalData approvalData, boolean expired);

	/**
	 * Encode a Collection of Approval and set it in ApprovalData object.
	 * @param approvals cannot be null.
	 */
	void setApprovals(ApprovalData approvalData, Collection<Approval> approvals);
	
	ApprovalData findNonExpiredApprovalDataLocal(int approvalId);
	
	/**
	 * Returns a list of all approval requests whose status is WAITING_FOR_APPROVAL only (aka. not including status APPROVED).
	 * This method is called mainly when upgrading older approval requests to EJBCA 6.6.0 or later.
	 * 
	 * @return A list of all approval requests whose status is WAITING_FOR_APPROVAL
	 */
	List<ApprovalData> findWaitingForApprovalApprovalDataLocal();
	
    /**
     * Method that takes an approvalId (hash) and returns the request's ID (the value in the "Id" column in the "ApprovalData" table in the database)
     * 
     * @param approvalId the request hash (approvalId in the database)
     * @return the ID of the approval request or 0 if it does not exist
     */
    int getIdFromApprovalId(int approvalId);

	 /**
      * Updates the approval request field for an approval. Doesn't do any authorization checks.
      * 
      * @param approvalDataId the ID of an approvalData object (not the approvalID hash)
      * @param approvalRequest the updated approval request
      */
     void updateApprovalRequest(final int approvalDataId, final ApprovalRequest approvalRequest);
     
     /**
      * Moves the expiration date forward and sets the status for Waiting for Approval. Doesn't do any authorization checks.
      * 
      * @param authenticationToken The administrator requesting extension of the request. Used for audit logging only.
      * @param approvalDataId Id of the approval request
      * @param extendForMillis The new expiration date will be set to current time plus this number of milliseconds
      * @throws IllegalStateException if the request has been approved or denied already.
      */
     void extendApprovalRequestNoAuth(AuthenticationToken authenticationToken, int approvalDataId, long extendForMillis);
     
     /**
      * Method returning a list of approvals from the give query
      * 
      * @param query should be a Query object containing ApprovalMatch and
      *            TimeMatch
      * @param index where the ResultSet should start
      * @param numberofrows maximum number of rows 
      * @param caAuthorizationString
      *            a list of authorized CA Ids in the form 'cAId=... OR cAId=...'
      * @param endEntityProfileAuthorizationString
      *            a list of authorized end entity profile ids in the form
      *            '(endEntityProfileId=... OR endEntityProfileId=...) objects
      *            only
      * @return a List of ApprovalDataVO, never null
      * @throws IllegalQueryException
      */
     List<ApprovalDataVO> query(final Query query, int index, int numberofrows, String caAuthorizationString,
             String endEntityProfileAuthorizationString) throws IllegalQueryException;
     
     /**
      * Returns a list of non-expired approvals with the given statuses.
      * @param includeUnfinished Includes requests that haven't been executed or rejected yet.
      * @param includeProcessed Includes requests that have been approved and executed, or rejected.
      * @param includeExpired Includes requests that have expired.
      * @param startDate Include requests from this date and later, or null for no limit.
      * @param endDate Include requests up to this date, or null for no limit.
      * @param expiresBefore When searching unfinished requests, include only those that expire before this date. Set to null to include all.
      * @param index where the ResultSet should start
      * @param numberofrows maximum number of rows
      * @param caAuthorizationString
      *            a list of authorized CA Ids in the form 'cAId=... OR cAId=...'
      * @param endEntityProfileAuthorizationString
      *            a list of authorized end entity profile ids in the form
      *            '(endEntityProfileId=... OR endEntityProfileId=...) objects
      *            only
      * @return a List of ApprovalDataVO, never null
      */
     List<ApprovalDataVO> queryByStatus(boolean includeUnfinished, boolean includeProcessed, boolean includeExpired,
             final Date startDate, final Date endDate, final Date expiresBefore, int index, int numberofrows, String caAuthorizationString,
             String endEntityProfileAuthorizationString);
}
