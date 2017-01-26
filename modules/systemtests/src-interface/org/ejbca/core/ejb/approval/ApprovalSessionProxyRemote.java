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

import java.util.Date;
import java.util.List;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * @version $Id$
 *
 */
@Remote
public interface ApprovalSessionProxyRemote {

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
     * @see ApprovalSessionBean#queryByStatus(boolean, boolean, boolean, java.util.Date, java.util.Date, java.util.Date, int, int, String, String)
     */
    List<ApprovalDataVO> queryByStatus(boolean includeUnfinished, boolean includeProcessed, boolean includeExpired, Date startDate, Date endDate, Date expiresBefore,
            int index, int numberofrows, String caAuthorizationString, String endEntityProfileAuthorizationString);
    
    /**
     * Extends the validity of an approval request.
     * @param authenticationToken Admin, only used for audit logging.
     * @param approvalRequestId ID of approval request.
     * @param extendForMillis Milliseconds to extend the request by.
     */
    void extendApprovalRequestNoAuth(AuthenticationToken authenticationToken, int approvalRequestId, long extendForMillis);
}
