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
package org.ejbca.core.ejb.ra;

import java.util.Collection;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityManagementProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityManagementProxySessionBean implements EndEntityManagementProxySessionRemote{

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    
    @Override
    public int decRequestCounter(String username) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException,
            WaitingForApprovalException {
        return endEntityManagementSession.decRequestCounter(username);
    }
    
    @Override
    public Collection<EndEntityInformation> query(AuthenticationToken admin, Query query, String caauthorizationstring,
            String endentityprofilestring, int numberofrows, final String endentityAccessRule) throws IllegalQueryException {
        return endEntityManagementSession.query(admin, query, caauthorizationstring, endentityprofilestring, numberofrows, endentityAccessRule);
    }
}
