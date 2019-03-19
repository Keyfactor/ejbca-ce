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
package org.cesecore.certificates.ca;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;

/**
 * Session bean used by functional tests in order to access local EJB interfaces of CaSession
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CaTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CaTestSessionBean implements CaTestSessionRemote {

    @EJB
    private CaSessionLocal caSession;

	@Override
	public CA getCA(AuthenticationToken admin, int caid) throws AuthorizationDeniedException {
		return (CA)caSession.getCA(admin, caid);
	}

	@Override
	public CA getCA(AuthenticationToken admin, String name) throws AuthorizationDeniedException {
		return (CA)caSession.getCA(admin, name);
	}
}
