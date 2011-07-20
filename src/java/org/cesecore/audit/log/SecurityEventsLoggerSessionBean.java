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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;

/**
 * This class implements the SecurityEventsLogger interface. It handles the
 * creation of a signed log for an event.
 * 
 * Based on CESeCore version:
 *      SecurityEventsLoggerSessionBean.java 921 2011-07-01 19:23:27Z johane
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SecurityEventsLoggerSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SecurityEventsLoggerSessionBean implements SecurityEventsLoggerSessionLocal, SecurityEventsLoggerSessionRemote {

    private static final Logger log = Logger.getLogger(SecurityEventsLoggerSessionBean.class);

    @EJB
    private InternalSecurityEventsLoggerSessionLocal internalSecurityEventsLoggerSession;

    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    @Override
    public void log(EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken)
            throws AuditRecordStorageException {
        log(eventType, eventStatus, module, service, authToken, null, null, null, null);
    }

    @Override
    public void log(EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken, String customId, String searchDetail1, String searchDetail2,
            Map<String, Object> additionalDetails) throws AuditRecordStorageException {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">log:%s:%s:%s:%s:%s:%s:%s:%s:%s", eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails));
        }
        try {
        	final TrustedTime tt = trustedTimeWatcherSession.getTrustedTime(false);
        	internalSecurityEventsLoggerSession.log(tt, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails);
        } catch (AuditRecordStorageException e) {
        	throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuditRecordStorageException(e.getMessage(), e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<log");
            }
        }
    }
}
