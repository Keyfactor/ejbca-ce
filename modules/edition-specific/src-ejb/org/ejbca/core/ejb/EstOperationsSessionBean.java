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
package org.ejbca.core.ejb;

import java.security.cert.X509Certificate;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.est.EstOperationsSessionLocal;
import org.ejbca.core.protocol.est.EstOperationsSessionRemote;

/**
 * Class that receives a EST message and passes it on to the correct message handler.
 * Not available in Community Edition
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EstOperationsSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EstOperationsSessionBean implements EstOperationsSessionLocal, EstOperationsSessionRemote {

	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public byte[] dispatchRequest(AuthenticationToken authenticationToken, String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody) 
	        throws UnsupportedOperationException{
        throw new UnsupportedOperationException("EST calls are only supported in EJBCA Enterprise");
	}

}
