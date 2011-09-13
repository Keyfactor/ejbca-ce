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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;

/**
 * This class implements the SecurityEventsLogger interface. It handles the
 * creation of a signed log for an event.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SecurityEventsLoggerSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SecurityEventsLoggerSessionBean implements SecurityEventsLoggerSessionLocal, SecurityEventsLoggerSessionRemote {

    private static final Logger log = Logger.getLogger(SecurityEventsLoggerSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private InternalSecurityEventsLoggerSessionLocal internalSecurityEventsLoggerSession;
    @EJB
    private AccessControlSessionLocal accessSession;

    @Override
    public void log(final AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service)
            throws AuditRecordStorageException, AuthorizationDeniedException {
        log(authToken, eventType, eventStatus, module, service, null, null, null, null);
    }

    @Override
    public void log(final AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String customId, String searchDetail1, String searchDetail2,
            Map<String, Object> additionalDetails) throws AuditRecordStorageException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">log:%s:%s:%s:%s:%s:%s:%s:%s:%s", eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails));
        }
        
        // We need to check that admin have rights to log
        if (!accessSession.isAuthorized(authToken, StandardRules.AUDITLOGLOG.resource())) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.AUDITLOGLOG.resource(), null);
            throw new AuthorizationDeniedException(msg);
        }

        try {
        	internalSecurityEventsLoggerSession.log(eventType, eventStatus, module, service, authToken.toString(), customId, searchDetail1, searchDetail2, additionalDetails);
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
