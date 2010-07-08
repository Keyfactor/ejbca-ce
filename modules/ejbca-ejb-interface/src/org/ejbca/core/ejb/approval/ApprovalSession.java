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

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * @author mikek
 * 
 */
public interface ApprovalSession {

    /**
     * Method used to add an approval to database. The main key of an approval
     * is the approval id, which should be unique for one administrator doing
     * one type of action, requesting the same action twice should result in the
     * same approvalId If the approvalId already exists, with a non expired
     * approval an ApprovalException is thrown otherwise is an new approval
     * request added to the database
     * 
     * @throws ApprovalException
     *             if an approval already exists for this request.
     */
    public void addApprovalRequest(Admin admin, ApprovalRequest approvalRequest,
            GlobalConfiguration gc) throws ApprovalException;

    /**
     * Method used to approve an approval requests. It does the follwing 1.
     * checks if the approval with the status waiting exists, throws an
     * ApprovalRequestDoesntExistException otherwise 2. check if the
     * administrator is authorized using the follwing rules: 2.1 if
     * getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     * authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise
     * AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     * end entity profile. 2.2 Checks if the admin is authoried to the approval
     * requests getCAId() 3. looks upp the username of the administrator and
     * checks that no approval have been made by this user earlier. 4. Runs the
     * approval command in the end entity bean.
     * 
     * @param admin
     * @param approvalId
     * @param approval
     * @param gc
     *            is the GlobalConfiguration used for notification info
     * @throws ApprovalRequestExpiredException
     * @throws ApprovalRequestExecutionException
     * @throws AuthorizationDeniedException
     * @throws ApprovalRequestDoesntExistException
     * @throws AdminAlreadyApprovedRequestException
     * @throws EjbcaException
     */
    public void approve(Admin admin, int approvalId, Approval approval,
            GlobalConfiguration gc) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException,
            AdminAlreadyApprovedRequestException, EjbcaException;

    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved action. If goes through all approvalrequests with the
     * given Id and checks their status, if any have status approved it returns
     * STATUS_APPROVED. This method should be used by action requiring the
     * requesting administrator to poll to see if it have been approved and only
     * have one step, othervise use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the
     *         ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalException
     *             if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     */
    public int isApproved(Admin admin, int approvalId, int step) throws ApprovalException,
            ApprovalRequestExpiredException;

    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved. This is the default method for simple single step
     * approvals. If goes through all approvalrequests with the given Id and
     * checks their status, if any have status approved it returns
     * STATUS_APPROVED. This method should be used by action requiring the
     * requesting administrator to poll to see if it have been approved and only
     * have one step, othervise use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the
     *         ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException
     *             if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     */
    public int isApproved(Admin admin, int approvalId) throws ApprovalException,
            ApprovalRequestExpiredException;

    /**
     * Method that marks a certain step of a a non-executable approval as done.
     * When the last step is performed the approvel is marked as EXPRIED.
     * 
     * @param admin
     * @param approvalId
     * @param step
     *            in approval to mark
     * @throws ApprovalException
     *             if approvalId doesn't exists,
     */
    public void markAsStepDone(Admin admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException;

    /**
     * Method used to remove an approval from database.
     * 
     * @param id
     *            , the uniqu id of the approvalrequest, not the same as
     *            approvalId
     * @throws ApprovalException
     */
    public void removeApprovalRequest(Admin admin, int id) throws ApprovalException;

    /**
     * Method used to reject an approval requests. It does the follwing 1.
     * checks if the approval with the status waiting exists, throws an
     * ApprovalRequestDoesntExistException otherwise 2. check if the
     * administrator is authorized using the follwing rules: 2.1 if
     * getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     * authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise
     * AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     * end entity profile. 2.2 Checks if the admin is authoried to the approval
     * requests getCAId() 3. looks upp the username of the administrator and
     * checks that no approval have been made by this user earlier. 4. Runs the
     * approval command in the end entity bean.
     * 
     * @param admin
     * @param approvalId
     * @param approval
     * @param gc
     *            is the GlobalConfiguration used for notification info
     * @throws ApprovalRequestExpiredException
     * @throws AuthorizationDeniedException
     * @throws ApprovalRequestDoesntExistException
     * @throws ApprovalException
     * @throws AdminAlreadyApprovedRequestException
     */
    public void reject(Admin admin, int approvalId, Approval approval,
            GlobalConfiguration gc) throws ApprovalRequestExpiredException,
            AuthorizationDeniedException, ApprovalException,
            AdminAlreadyApprovedRequestException;
    
    
}
