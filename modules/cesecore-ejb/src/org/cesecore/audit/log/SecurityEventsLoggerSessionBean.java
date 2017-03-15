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

import java.util.LinkedHashMap;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * This class implements the SecurityEventsLogger interface. It handles the
 * creation of a signed log for an event.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SecurityEventsLoggerSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class SecurityEventsLoggerSessionBean implements SecurityEventsLoggerSessionLocal, SecurityEventsLoggerSessionRemote {

    private static final Logger log = Logger.getLogger(SecurityEventsLoggerSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private InternalSecurityEventsLoggerSessionLocal internalSecurityEventsLoggerSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    @Override
    public void log(final AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service)
            throws AuditRecordStorageException, AuthorizationDeniedException {
        log(authToken, eventType, eventStatus, module, service, null, null, null, null);
    }

    @Override
    public void log(final AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String customId, String searchDetail1, String searchDetail2,
            Map<String, Object> additionalDetails) throws AuditRecordStorageException, AuthorizationDeniedException {        
        // We need to check that admin have rights to log
        if (!authorizationSession.isAuthorized(authToken, AuditLogRules.LOG.resource())) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AuditLogRules.LOG.resource(), null);
            throw new AuthorizationDeniedException(msg);
        }
        log(eventType, eventStatus, module, service, authToken.toString(), customId, searchDetail1, searchDetail2, additionalDetails);
    }
    
    @Override
    public void log(final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service, final String authToken, final String customId, final String searchDetail1, final String searchDetail2,
            final String additionalDetailsMsg) throws AuditRecordStorageException {
        final Map<String, Object> additionalDetails = new LinkedHashMap<String, Object>();
        additionalDetails.put("msg", additionalDetailsMsg);
        log(eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails);
    }

    @Override
    public void log(final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service, final String authToken, final String customId, final String searchDetail1, final String searchDetail2,
            final Map<String, Object> additionalDetails) throws AuditRecordStorageException {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">log:%s:%s:%s:%s:%s:%s:%s:%s:%s", eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails));
        }
        try {
            final TrustedTime tt = trustedTimeWatcherSession.getTrustedTime(false);
            internalSecurityEventsLoggerSession.log(tt, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails);
        } catch (TrustedTimeProviderException e) {
            log.error(e.getMessage(), e);
            throw new AuditRecordStorageException(e.getMessage(), e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<log");
            }
        }
    }
}
