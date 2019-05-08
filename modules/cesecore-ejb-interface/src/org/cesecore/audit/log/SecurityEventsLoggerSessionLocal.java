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

import javax.ejb.Local;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.dbprotection.DatabaseProtectionException;

/**
 * Local interface for the SecurityEventsLogger
 * 
 * @version $Id$
 */
@Local
public interface SecurityEventsLoggerSessionLocal extends SecurityEventsLoggerSession {
	
    /** Gets trusted time, then calls log
     * 
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service(application) that performed the operation.
     * @param authToken The authentication token that invoked the operation.
     * @param customId A custom identifier related to this event (e.g. a CA's identifier)
     * @param searchDetail1 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a certificate serialnumber)
     * @param searchDetail2 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a username)
     * @param additionalDetails Additional details to be logged.
     * @throws AuditRecordStorageException
     */
	void log(EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken, 
			String customId, String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails) throws AuditRecordStorageException;

    /** Gets trusted time, then calls log
     * 
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service(application) that performed the operation.
     * @param authToken The authentication token that invoked the operation.
     * @param customId A custom identifier related to this event (e.g. a CA's identifier)
     * @param searchDetail1 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a certificate serialnumber)
     * @param searchDetail2 A detail of this event that can be queried for using QueryCriteria (database) searches (e.g. a username)
     * @param additionalDetailsMsg A single additional details String to be logged.
     * @throws AuditRecordStorageException
     */
    void log(EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken, 
            String customId, String searchDetail1, String searchDetail2, String additionalDetailsMsg) throws AuditRecordStorageException;
    
    /**
     * Perform a health check on the audit log device. 
     * @throws DatabaseProtectionException if database protection is enabled, and the audit log does not function
     */
    void healthCheck() throws DatabaseProtectionException;

}
