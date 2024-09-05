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

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Acts as a proxy for IntegrityProtectedAuditorSessionBean
 *
 *
 */
@TransactionAttribute(TransactionAttributeType.REQUIRED)
@Stateless
public class IntegrityProtectedAuditorProxySessionBean implements IntegrityProtectedAuditorProxySessionRemote  {

    @EJB
    private IntegrityProtectedAuditorSessionLocal integrityProtectedAuditorSession; 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int deleteRows(final AuthenticationToken token, final Date timestamp, final Properties properties) throws AuthorizationDeniedException {
        return integrityProtectedAuditorSession.deleteRows(token, timestamp, properties);
    }
}
