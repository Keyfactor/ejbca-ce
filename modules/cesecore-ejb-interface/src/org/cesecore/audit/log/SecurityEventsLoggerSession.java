/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.audit.log;

import java.util.Map;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * This interface provides access to storing security audit log entries.
 * 
 * @version $Id: SecurityEventsLoggerSession.java 167 2011-01-27 09:11:21Z tomas$
 */
public interface SecurityEventsLoggerSession {

    /**
     * Creates a signed log, stored in the database.
     * 
     * @param authToken The authentication token of the entity that invoked the operation.
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service (application) that performed the operation.
     * @throws AuditRecordStorageException 
     * @throws AuthorizationDeniedException 
     */
    public void log(AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service)
            throws AuditRecordStorageException, AuthorizationDeniedException;

    /**
     * Creates a signed log, stored in the database.
     * 
     * @param authToken The authentication token of the entity that invoked the operation.
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service (application) that performed the operation.
     * @param customId A custom identifier related to this event (e.g. a CA's identifier)
     * @param searchDetail1 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a certificate serialnumber)
     * @param searchDetail2 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a username)
     * @param additionalDetails Additional details of this event to be stored in a non-searchable manner.
     * @throws AuditRecordStorageException 
     * @throws AuthorizationDeniedException 
     */
    void log(AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String customId, String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails)
            throws AuditRecordStorageException, AuthorizationDeniedException;
}
