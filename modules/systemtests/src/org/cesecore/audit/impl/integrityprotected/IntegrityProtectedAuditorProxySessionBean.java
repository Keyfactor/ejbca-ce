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
package org.cesecore.audit.impl.integrityprotected;

import java.util.Date;
import java.util.Properties;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;

/**
 * Acts as a proxy for IntegrityProtectedAuditorSessionBean
 * 
 * @version $Id$
 *
 */
@TransactionAttribute(TransactionAttributeType.REQUIRED)
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "IntegrityProtectedAuditorProxySessionRemote")
public class IntegrityProtectedAuditorProxySessionBean implements IntegrityProtectedAuditorProxySessionRemote  {

    @EJB
    private IntegrityProtectedAuditorSessionLocal integrityProtectedAuditorSession; 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int deleteRows(final AuthenticationToken token, final Date timestamp, final Properties properties) throws AuthorizationDeniedException {
        return integrityProtectedAuditorSession.deleteRows(token, timestamp, properties);
    }
}
