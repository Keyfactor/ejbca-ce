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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalDataVO;

@Local
public interface ApprovalExecutionSessionLocal extends ApprovalExecutionSession {

    /**
     * Asserts general authorization to approve 
     * @throws AuthorizationDeniedException if any authorization error occurred  
     */
    void assertAuthorizedToApprove(AuthenticationToken admin, ApprovalDataVO approvalData) throws AuthorizationDeniedException;
}
