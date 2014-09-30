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
package org.ejbca.core.ejb.audit;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;

/**
 * Proxy to make EjbcaAuditorSessionLocal testable over RMI.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaAuditorTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbcaAuditorTestSessionBean implements EjbcaAuditorTestSessionRemote {

    @EJB
    private EjbcaAuditorSessionLocal ejbcaAuditorSession;
    
    @Override
    public List<? extends AuditLogEntry> selectAuditLog(AuthenticationToken token, String device, int firstResult, int maxResults, String whereClause,
            String orderClause, List<Object> parameters) throws AuthorizationDeniedException {
        return ejbcaAuditorSession.selectAuditLog(token, device, firstResult, maxResults, whereClause, orderClause, parameters);
    }
}
