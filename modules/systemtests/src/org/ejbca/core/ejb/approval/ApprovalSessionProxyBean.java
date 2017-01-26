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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalSessionProxyBean implements ApprovalSessionProxyRemote {

    @EJB
    private ApprovalSessionLocal approvalSession;

    @Override
    public List<ApprovalDataVO> query(Query query, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString) throws IllegalQueryException {
        return approvalSession.query(query, index, numberofrows, caAuthorizationString, endEntityProfileAuthorizationString);
    }

    @Override
    public List<ApprovalDataVO> queryByStatus(boolean includeUnfinished, boolean includeProcessed, boolean includeExpired, Date startDate, Date endDate,
            Date expiresBefore, int index, int numberofrows, String caAuthorizationString, String endEntityProfileAuthorizationString) {
        return approvalSession.queryByStatus(includeUnfinished, includeProcessed, includeExpired, startDate, endDate, expiresBefore,
                index, numberofrows, caAuthorizationString, endEntityProfileAuthorizationString);
    }
    
    @Override
    public void extendApprovalRequestNoAuth(final AuthenticationToken authenticationToken, final int approvalRequestId, final long extendForMillis) {
        approvalSession.extendApprovalRequestNoAuth(authenticationToken, approvalRequestId, extendForMillis);
    }

}
