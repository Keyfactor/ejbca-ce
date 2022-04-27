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

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;

/** 
 * Session bean to manage approval requests, i.e. add and find.
 */
public interface ApprovalSession {

    /**
     * Method used to add an approval to database.
     * 
     * The main key of an approval is the approvalId, which should be unique
     * for one administrator doing one type of action, requesting the same
     * action twice should result in the same approvalId
     * 
     * If the approvalId already exists, with a non expired approval, a new approval request is added to the database. An approvalException is thrown otherwise
     * 
     * @param admin administrator, will be added to the list of admins who have edited the request.
     * @param approvalRequest the request to add to the database
     * @return the database identifier (requestID of the created request)
     * 
     * @throws ApprovalException
     *             if an approval already exists for this request.
     */
     int addApprovalRequest(AuthenticationToken admin, ApprovalRequest approvalRequest) throws ApprovalException;

     /**
      * Adds an approval request (for ACME account registration or account key change).
      * 
      * @param admin the authentication token.
      * @param approvalRequestType the approval Type ({@link ApprovalRequestType#ACMEACCOUNTREGISTRATION} and {@link ApprovalRequestType#ACMEACCOUNTKEYCHANGE}).
      * @param approvalProfileId the approval profile ID.
      * @param endEntityProfileId the end entity profile ID.
      * @param acmeAccountId the ACME account ID (=public key fingerprint).
      * @return the ID of the approval request or null, if no approval request could be created and stored.
      * @throws ApprovalException if an approval request with this ID already exists.
      */
     Integer createApprovalRequest(AuthenticationToken admin, int approvalRequestType, int approvalProfileId, int endEntityProfileId, String acmeAccountId) throws ApprovalException;
     
     /**
      * Checks if the approval request by the given identifier is approved or not. 
      * 
      * 
      * This method should be used by action requiring the requesting administrator to poll to see if it have been approved and only have one
      * step, otherwise use the method with the step parameter.
      * 
      * If the return value is:
      * 0    the request is approved (ApprovalDataVO.STATUS_APROVED) 
      * >0   the request requires so many more approvals left 
      * <0   the request has any other status 
      * 
      * @param approvalId the approvalID (hash) of the request
      * @param step the given step 
      * @return the number of approvals left if still waiting for approval, 0 (ApproApprovalDataVO.STATUS_APROVED) if approved, otherwise the ApprovalDataVO.STATUS constant returned indicating the status.
      * @throws ApprovalException if approvalId does not exist
      * @throws ApprovalRequestExpiredException thrown one time if one or more of the approvals has expired, once notified it wont throw it anymore. 
      * But If the request is multiple steps and user have already performed that step, the exception will always be thrown.
      */
     int isApproved(int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Checks if the approval request by the given identifier is approved or not. 
     * 
     * 
     * This method should be used by action requiring the requesting administrator to poll to see if it have been approved and only have one
     * step, otherwise use the method with the step parameter.
     * 
     * If the return value is:
     * 0    the request is approved (ApprovalDataVO.STATUS_APROVED) 
     * >0   the request requires so many more approvals left 
     * <0   the request has any other status 
     * 
     * @param admin an authentication token
     * @param approvalId the approvalID (hash) of the request
     * @return the number of approvals left if still waiting for approval, 0 (ApprovalDataVO.STATUS_APROVED) 
     * if approved otherwise the ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException if approvalId does not exist
     * @throws ApprovalRequestExpiredException thrown one time if one or more of the approvals has expired, once notified it wont throw it anymore. 
     * But If the request is multiple steps and user have already performed that step, the exception will always be thrown.
     */
    int isApproved(int approvalId) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Returns the current status of a given approval request.
     * 
     * @param approvalId the approvalID (hash) of the request
     * @return the current status of the request
     * @throws ApprovalException thrown if there's no request with the given status
     */
    int getStatus(int approvalId) throws ApprovalException;
    
    /**
     * Gives the remaining number of approvals for a given approval request
     * 
     * @param requestId the unique requestId of the approval request, not the same as approvalId
     * @return the remaining number of approvals for this request (with 0 meaning that the request has passed) or -1 if the request has been denied
     * @throws ApprovalException if an approval request with the given ID was not found. 
     * @throws ApprovalRequestExpiredException if approval request was expired before having a definite status
     */
    int getRemainingNumberOfApprovals(int requestId) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method that marks a certain step of a a non-executable approval as done.
     * When the last step is performed the approval is marked as EXPRIED.
     * 
     * @param approvalId the approvalID (hash) of the request
     * @param step in approval to mark
     * @throws ApprovalException if approvalId does not exist,
     * 
     * @deprecated Used for the old hard token era steps. 
     */
    @Deprecated
    void markAsStepDone(int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method used to remove an approval from database.
     * 
     * @param admin administrator, will be added to the list of admins who have edited the request.
     * @param requestId the unique requestId of the approval request, not the same as approvalId
     */
    void removeApprovalRequest(AuthenticationToken admin, int requestId);
    
    /**
     * Changes an approval request. The administrator will be blacklisted from approving the request.
     * This operation changes the approvalId (the hash of the request), but not the id of the request.
     * 
     * @param admin administrator, will be added to the list of admins who have edited the request.
     * @param requestId the unique requestID of the approval request, not the same as approvalID.
     * @param approvalRequest modified request
     * @throws ApprovalException if the approval request does not exist, or may not be edited.
     */
    void editApprovalRequest(AuthenticationToken admin, int requestId, ApprovalRequest approvalRequest) throws ApprovalException;

    /**
     * Method returning an approval requests with status 'waiting', 'Approved'
     * or 'Reject' returns null if no non expired exists
     * 
     * @param approvalId the approvalID (hash) of the request
     * @return ApprovalDataVO or null if the approval does not exist.
     */
    ApprovalDataVO findNonExpiredApprovalRequest(int approvalId);

    /**
     * Method that takes an approvalId and returns all approval requests for this.
     * To search by ID, use {@link #findApprovalDataByRequestId} instead.
     * 
     * @param approvalId the approvalID (hash) of the request
     * @return an unsorted by request date) list of ApprovalDataVO, empty if no approvals exists, never null.
     */
    List<ApprovalDataVO> findApprovalDataVO(int approvalId);

    /**
     * Method that returns a given approval, by ID.
     * To search by hash, use {@link #findApprovalDataVO} instead.
     * 
     * @param requestId ID of approval request (not an approvalID, which is a hash) 
     * @return ApprovalDataVO, or null if non-existent
     */
    ApprovalDataVO findApprovalDataByRequestId(int requestId);

    /**
     * Update the approval/view rights of the Approval
     * 
     * @param admin administrator triggering the approval rights update
     * @param roleId the affected role which needs an approval rights refresh
     * @param roleName the name of the affected role
     * @throws AuthorizationDeniedException if the user is not authorized to perform this action.
     */    
    void updateApprovalRights(AuthenticationToken admin, int roleId, String roleName) throws AuthorizationDeniedException;

}
