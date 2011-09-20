/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;

/**
 * Mock implementation injected into CertificateStoreSessionBean when
 * EJBCA is deployed in stand alone VA mode. This avoid code duplication
 * and dragging along unwanted dependencies, since the methods in this
 * class are only used when CertificateData is changed (which should
 * never happen in stand alone VA mode.)
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class StandAloneVaMockSessionBean implements AccessControlSessionLocal, SecurityEventsLoggerSessionLocal{

	@Override
	public void forceCacheExpire() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isAuthorized(AuthenticationToken authenticationToken, String resource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String resource) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void log(EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken, String customId,
			String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails) throws AuditRecordStorageException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void log(AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service)
			throws AuditRecordStorageException, AuthorizationDeniedException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void log(AuthenticationToken authToken, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String customId,
			String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails) throws AuditRecordStorageException, AuthorizationDeniedException {
		throw new UnsupportedOperationException();
	}
}
