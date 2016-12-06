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

import java.util.List;

import javax.ejb.Remote;

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
     * Returns a list of non-expired approvals with the given statuses.
     * @param includeUnfinished Includes requests that haven't been executed or rejected yet.
     * @param includeProcessed Includes requests that have been approved and executed, or rejected.
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
    List<ApprovalDataVO> queryByStatus(final boolean includeUnfinished, final boolean includeProcessed, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString);
}
