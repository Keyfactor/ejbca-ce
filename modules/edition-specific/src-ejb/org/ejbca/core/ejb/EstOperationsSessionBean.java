/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
