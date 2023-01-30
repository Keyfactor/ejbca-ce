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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.its.EtsiEcaOperationsSessionLocal;
import org.ejbca.core.ejb.its.EtsiEcaOperationsSessionRemote;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EtsiEcaOperationsSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EtsiEcaOperationsSessionBean implements EtsiEcaOperationsSessionLocal, EtsiEcaOperationsSessionRemote {

    @Override
    public byte[] doEtsiOperation(AuthenticationToken authenticationToken, String ecaCertificateId, 
                    byte[] requestBody, int operationCode)
            throws AuthorizationDeniedException, EjbcaException {
        throw new UnsupportedOperationException("ECA operations are only supported in EJBCA Enterprise");
    }

}
