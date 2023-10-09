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

import javax.ejb.Remote;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * @see EjbcaAuditorSession
 */
@Remote
public interface EjbcaAuditorTestSessionRemote extends EjbcaAuditorSession {
    
    public List<? extends AuditLogEntry> selectAuditLogNoAuth(final AuthenticationToken token, final String device, final int firstResult, final int maxResults,
            final String whereClause, final String orderClause, final List<Object> parameters) throws AuthorizationDeniedException;
    
}
