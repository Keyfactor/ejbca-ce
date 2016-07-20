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

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;

/**
 * 
 * @version $Id$
 *
 */

public interface ApprovalExecutionSession {

    /**
     * Method used to approve an approval requests.
     * 
     * It does the following 1. checks if the approval with the status waiting
     * exists, throws an ApprovalRequestDoesntExistException otherwise
     * 
     * 2. check if the administrator is authorized using the following rules:
     * 2.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     * authorized to AccessRulesConstants.REGULAR_APPROVECAACTION otherwise
     * AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     * end entity profile.
     * 2.2 Checks if the admin is authorized to the approval requests getCAId()
     * 
     * 3. looks up the username of the administrator and checks that no
     * approval have been made by this user earlier.
     * 
     * 4. Runs the approval command in the end entity bean.
     * 
     * @param admin The administrator approving the request
     * @param approvalId the approvalId of the request that the admin tries to approve
     * @param approval the new approval to vet
     * 
     * @throws ApprovalRequestExpiredException
     * @throws ApprovalRequestExecutionException
     * @throws AuthorizationDeniedException if the admin wasn't authorized to perform approvals, or wasn't authorized to the particular approval 
     *          profile
     * @throws ApprovalRequestDoesntExistException
     * @throws AdminAlreadyApprovedRequestException if the admin has already approved the action before
     * @throws SelfApprovalException if the administrator performing the approval is the same as the one requesting the original action. 
     * @throws AuthenticationFailedException if the authentication token failed to authenticate
     */
    void approve(AuthenticationToken admin, int approvalId, Approval approval) throws ApprovalRequestExpiredException,
            ApprovalRequestExecutionException, AuthorizationDeniedException, AdminAlreadyApprovedRequestException, 
            ApprovalException, SelfApprovalException, AuthenticationFailedException;
    
    /**
     * Method used to reject an approval requests.
     * 
     * It does the following 1. checks if the approval with the status waiting
     * exists, throws an ApprovalRequestDoesntExistException otherwise
     * 
     * 2. check if the administrator is authorized using the following rules: 
     *   2.1 If the approval profile is of type AccumulativeApprovalProfile:
     *      2.1.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     *            authorized to AccessRulesConstants.REGULAR_APPROVECAACTION otherwise
     *            AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     *            end entity profile. 
     *      2.1.2 Checks if the admin is authorized to the approval requests getCAId()
     *   2.2 If the approval profile is of another type, check  whether the admin is authorized 
     *       by calling ApprovalprofileType.isAdminAllowedToApprove()
     * 
     * 3. looks up the username of the administrator and checks that no
     * approval have been made by this user earlier.
     * 
     * 4. Runs the approval command in the end entity bean.
     * 
     * @throws SelfApprovalException if the administrator performing the approval is the same as the one requesting the original action. 
     * @throws AuthenticationFailedException if the authentication token failed to authenticate
     */
    void reject(AuthenticationToken admin, int approvalId, Approval approval) 
            throws ApprovalRequestExpiredException, AuthorizationDeniedException, ApprovalException, AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException;
}
