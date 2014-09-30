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
package org.ejbca.cesecoreintegration;

import java.util.Map;
import java.util.Properties;

import javax.ejb.Stateless;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.queued.QueuedLoggerSessionLocal;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.TrustedTime;

/**
 * Mock implementation of QueuedDevice interface to allow the secure audit code imported from
 * CESeCore to stay the same without bundling the queued implementation.
 * 
 * @version $Id$
 */
@Stateless
public class QueuedLoggerMockSessionBean implements QueuedLoggerSessionLocal {

	private static final String UNSUPPORTED = "Unsupported operation. QueuedDevice is not bundled with EJBCA.";

	@Override
	public void log(TrustedTime trustedTime, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken,
			String customId, String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails, Properties properties) throws AuditRecordStorageException {
		throw new RuntimeException(UNSUPPORTED);
	}
}
