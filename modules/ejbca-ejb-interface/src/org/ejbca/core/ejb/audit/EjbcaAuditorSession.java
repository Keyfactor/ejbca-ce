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

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Workaround for the very complex CESeCore query criteria API.
 *
 * Allow fetching of logs in a more standard JPA fashion.
 *
 * @version $Id$
 */
public interface EjbcaAuditorSession {
    /**
     * Selects audit log records from the IntegrityProtectedLogDevice.
     * 
     * User input should never be supplied in the whereClause or orderClause, since this will result in SQL
     * injection attacks where more data than intended is returned.
     * 
     * @param token The auditors authentication token
     * @param device Must be "IntegrityProtectedLogDevice" for now.
     * @param firstResult first entry in result set
     * @param maxResults number of results to return. '0' means no limit.
     * @param whereClause corresponds to JPQL where statement. E.g. " a.columnSomething = ?0 AND a.columnSomethingElse > ?1 ..."
     * @param orderClause corresponds to JPQL order statement. E.g. " a.columnSomething ASC"
     * @param parameters Array of parameters in the order they appear in the whereClause
     * @return result of the executed query
     * @throws AuthorizationDeniedException if token is not authorized to StandardRules.AUDITLOGSELECT
     */
    List<? extends AuditLogEntry> selectAuditLog(AuthenticationToken token, String device, int firstResult, int maxResults, String whereClause, String orderClause, List<Object> parameters) throws AuthorizationDeniedException;
}
