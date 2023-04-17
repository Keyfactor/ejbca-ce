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
package org.ejbca.core.ejb.ca.sign;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.jndi.JndiConstants;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignProxySessionBean implements SignProxySessionRemote {

    @EJB
    private SignSessionLocal signSession;
    
    @Override
    public byte[] signPayload(byte[] data, int signingCaId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException {
        return signSession.signPayload(data, signingCaId);
    }

}
