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

import java.util.HashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.audit.LogServiceState;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedLoggerSessionLocal;
import org.cesecore.audit.impl.queued.QueuedLoggerSessionLocal;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;

/**
 * Internal logging without dependency on TrustedTime.
 * 
 * @version $Id$
 */  
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class InternalSecurityEventsLoggerSessionBean implements InternalSecurityEventsLoggerSessionLocal {

	private static final Logger LOG = Logger.getLogger(InternalSecurityEventsLoggerSessionBean.class);
	
    @EJB
    private QueuedLoggerSessionLocal queuedLoggerSession;
    @EJB
    private IntegrityProtectedLoggerSessionLocal integrityProtectedLoggerSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    @Override
    public void log(final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service, final String authToken, final String customId, final String searchDetail1, final String searchDetail2,
    		final Map<String, Object> additionalDetails) throws AuditRecordStorageException {
        try {
        	final TrustedTime tt = trustedTimeWatcherSession.getTrustedTime(false);
        	log(tt, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails);
        } catch (AuditRecordStorageException e) {
        	throw e;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new AuditRecordStorageException(e.getMessage(), e);
        } finally {
            if (LOG.isTraceEnabled()) {
            	LOG.trace("<log");
            }
        }
    }

    @Override
    public void log(final TrustedTime trustedTime, final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service, final String authToken,
    		final String customId, final String searchDetail1, final String searchDetail2, final Map<String, Object> additionalDetails) throws AuditRecordStorageException {
    	if (LogServiceState.INSTANCE.isDisabled()) {
    		throw new AuditRecordStorageException("Security audit logging is currently disabled.");
    	}
    	final Map<Class<?>, Object> ejbs = getEjbs();
    	boolean anyFailures = false;
        for (final String loggerId : AuditDevicesConfig.getAllDeviceIds()) {
        	try {
        		AuditDevicesConfig.getDevice(ejbs, loggerId).log(trustedTime, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails, AuditDevicesConfig.getProperties(loggerId));
        	} catch (Exception e) {	// AuditRecordStorageException
        		anyFailures = true;
        		LOG.error("AuditDevice " + loggerId + " failed. A event was not logged to this device!", e);
        	}
        }
        if (anyFailures) {
        	// CESeCore.FAU_STG.4.1: The TSF shall prevent audited events, except those taken by the Auditable and no other actions if the audit trail is full.
        	// So even if we failed to produce a proper audit trail for these events, we swallow the exception here to allow the operation to continue.
        	if (!eventType.equals(EventTypes.LOG_VERIFY) && !eventType.equals(EventTypes.LOG_EXPORT) && !eventType.equals(EventTypes.LOG_DELETE) && !eventType.equals(EventTypes.LOG_SIGN)  && !eventType.equals(EventTypes.LOG_MANAGEMENT_CHANGE)) {
            	throw new AuditRecordStorageException("Failed to write audit log to a least one device.");
        	}
        }
    }

    /** Propagate the injected SSBs, since we can't use application server agnostic EJB lookup in EJB 3.0. */
    private Map<Class<?>, Object> getEjbs() {
    	final Map<Class<?>, Object> ejbs = new HashMap<Class<? extends Object>, Object>();
    	ejbs.put(QueuedLoggerSessionLocal.class, queuedLoggerSession);
    	ejbs.put(IntegrityProtectedLoggerSessionLocal.class, integrityProtectedLoggerSession);
    	return ejbs;
    }
}
