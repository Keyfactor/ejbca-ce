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

import org.apache.commons.lang.time.StopWatch;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.audit.LogServiceState;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedLoggerSessionLocal;
import org.cesecore.audit.impl.queued.QueuedLoggerSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.time.TrustedTime;

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
                StopWatch sw = null;
                if(LOG.isDebugEnabled()){
                    sw = new StopWatch();
                    sw.start();
                }
                AuditDevicesConfig.getDevice(ejbs, loggerId).log(trustedTime, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails, AuditDevicesConfig.getProperties(loggerId));
                if(LOG.isDebugEnabled()){
                    sw.stop();
                    LOG.debug("LogDevice: "+ loggerId +" Proc: "+sw.getTime());
                }
            } catch (Exception e) { // AuditRecordStorageException
                anyFailures = true;
                LOG.error("AuditDevice " + loggerId + " failed. An event was not logged to this device!", e);
            }
        }
        if (anyFailures) {
            // CESeCore.FAU_STG.4.1: The TSF shall prevent audited events, except those taken by the Auditable and no other actions if the audit trail is full.
            // So even if we failed to produce a proper audit trail for these events, we swallow the exception here to allow the operation to continue.
            if (!eventType.equals(EventTypes.LOG_VERIFY) && !eventType.equals(EventTypes.LOG_EXPORT) && !eventType.equals(EventTypes.LOG_DELETE) && !eventType.equals(EventTypes.LOG_SIGN)  && !eventType.equals(EventTypes.LOG_MANAGEMENT_CHANGE)) {
                throw new AuditRecordStorageException("Failed to write audit log to at least one device.");
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
    
    @Override
    public boolean auditLogCryptoTest(final String protectThis) {
        if ( CesecoreConfiguration.useDatabaseIntegrityProtection(AuditRecordData.class.getSimpleName()) ) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Performing audit log integrity protection test.");
            }
            // Make a dummy auditRecordData object, to use the "real" code to calculate database integrity protection
            final AuditRecordData auditRecordData = new AuditRecordData("auditLogCryptoTest", 1L, System.currentTimeMillis(), EventTypes.LOG_VERIFY, EventStatus.VOID, null,
                    ServiceTypes.CORE, ModuleTypes.SECURITY_AUDIT, "auditLogCryptoTest", null, null, null);
            auditRecordData.calculateProtection();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Audit log integrity protection test completed successfully.");
            }
            return true;
        }
        return false;
    }

}
