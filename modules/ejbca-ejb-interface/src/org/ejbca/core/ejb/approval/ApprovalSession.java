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
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;

/** Session bean to manage approval requests, i.e. add and find.
 * 
 * @version $Id$
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
     * @return the database identifier of the created request
     * 
     * @throws ApprovalException
     *             if an approval already exists for this request.
     */
     int addApprovalRequest(AuthenticationToken admin, ApprovalRequest approvalRequest) throws ApprovalException;

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
      * @param approvalId the approval ID of the request
      * @param the given step 
      * @return the number of approvals left if still waiting for approval, 0 (ApprovalDataVO.STATUS_APROVED) 
      * if approved otherwise the ApprovalDataVO.STATUS constants returned indicating the status.
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
     * @param approval the ID of the request
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
     * @param approvalId the ID of the request
     * @return the current status of the request
     * @throws ApprovalException thrown if there's no request with the given status
     */
    int getStatus(int approvalId) throws ApprovalException;
    
    /**
     * Gives the remaining number of approvals for a given approval request
     * 
     * @param requestId the request ID of the approval
     * @return the remaining number of approvals for this request, or -1 if the request has been denied
     * @throws ApprovalException if an approval request with the given ID was not found. 
     * @throws ApprovalRequestExpiredException if approval request was expired
     */
    int getRemainingNumberOfApprovals(int requestId) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method that marks a certain step of a a non-executable approval as done.
     * When the last step is performed the approval is marked as EXPRIED.
     * 
     * @param approvalId
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
     * @param id the unique id of the approvalrequest, not the same as approvalId
     */
    void removeApprovalRequest(AuthenticationToken admin, int id);
    
    /**
     * Changes an approval request. The administrator will be blacklisted from approving the request.
     * This operation changes the approvalId (the hash of the request), but not the id of the request.
     * 
     * @param admin administrator, will be added to the list of admins who have edited the request.
     * @param id the unique id of the approvalrequest, not the same as approvalId.
     * @param approvalRequest modified request
     * @throws ApprovalException if the approval request does not exist, or may not be edited.
     */
    void editApprovalRequest(AuthenticationToken admin, int id, ApprovalRequest approvalRequest) throws ApprovalException;

    /**
     * Method returning an approval requests with status 'waiting', 'Approved'
     * or 'Reject' returns null if no non expired exists
     */
    ApprovalDataVO findNonExpiredApprovalRequest(int approvalId);

    /**
     * Method that takes an approvalId and returns all approval requests for this.
     * 
     * @param approvalId
     * @return and list of ApprovalDataVO, empty if no approvals exists.
     */
    List<ApprovalDataVO> findApprovalDataVO(int approvalId);


}
