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
package org.cesecore.audit;

import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * Interface for writing secure audit events.
 * 
 * @version $Id$
 */
public interface AuditLogger {
    /**
     * Creates a signed log, stored in the database.
     * 
     * @param trustedTime TrustedTime instance will be used to get a trusted timestamp.
     * @param eventType The event log type.
     * @param eventStatus The status of the operation to log.
     * @param module The module where the operation took place.
     * @param service The service(application) that performed the operation.
     * @param authToken The authentication token that invoked the operation.
     * @param additionalDetails Additional details to be logged.
     * @param properties properties to be passed on the device
     * 
     * @throws AuditRecordStorageException if unable to store the log record
     */
    void log(TrustedTime trustedTime, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken,
    		String customId, String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails, Properties properties) throws AuditRecordStorageException;
}
