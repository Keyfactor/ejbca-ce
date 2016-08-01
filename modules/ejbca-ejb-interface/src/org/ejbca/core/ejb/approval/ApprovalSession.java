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
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

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
     * If the approvalId already exists, with a non expired approval, a new approval
     * request is added to the database. An approvalException is thrown otherwise
     * 
     * @throws ApprovalException
     *             if an approval already exists for this request.
     */
     void addApprovalRequest(AuthenticationToken admin, ApprovalRequest approvalRequest) throws ApprovalException;

    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved action.
     * 
     * If goes through all approval requests with the given Id and checks their
     * status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting
     * administrator to poll to see if it have been approved and only have one
     * step, otherwise use the method with the step parameter.
     * 
     * @return the number of approvals left if still waiting for approval, 0 (ApprovalDataVO.STATUS_APROVED) 
     * if approved otherwise the ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException
     *             if approvalId does not exist
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     */
     int isApproved(AuthenticationToken admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved. This is the default method for simple single step
     * approvals.
     * 
     * If goes through all approvalrequests with the given Id and checks their
     * status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting
     * administrator to poll to see if it have been approved and only have one
     * step, otherwise use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left if still waiting for approval, 0 (ApprovalDataVO.STATUS_APROVED) 
     * if approved otherwise the ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException
     *             if approvalId does not exist
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     */
    int isApproved(AuthenticationToken admin, int approvalId) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method that marks a certain step of a a non-executable approval as done.
     * When the last step is performed the approval is marked as EXPRIED.
     * 
     * @param admin
     * @param approvalId
     * @param step in approval to mark
     * @throws ApprovalException if approvalId does not exist,
     */
    void markAsStepDone(AuthenticationToken admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException;

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
    ApprovalDataVO findNonExpiredApprovalRequest(AuthenticationToken admin, int approvalId);

    /**
     * Method that takes an approvalId and returns all approval requests for this.
     * 
     * @param admin
     * @param approvalId
     * @return and list of ApprovalDataVO, empty if no approvals exists.
     */
    List<ApprovalDataVO> findApprovalDataVO(AuthenticationToken admin, int approvalId);
    
    /**
     * Method that takes an approvalId and returns the request's Id (the value in the "Id" column in the "ApprovalData" table in the database)
     * 
     * @param admin
     * @param approvalId
     * @return the Id of the approval request
     */
    int getIdFromApprovalId(AuthenticationToken admin, int approvalId);

    /**
     * Method returning a list of approvals from the give query
     * 
     * @param admin
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
     * @throws AuthorizationDeniedException
     * @throws IllegalQueryException
     */
    List<ApprovalDataVO> query(AuthenticationToken admin, Query query, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString) throws AuthorizationDeniedException, IllegalQueryException;
}
