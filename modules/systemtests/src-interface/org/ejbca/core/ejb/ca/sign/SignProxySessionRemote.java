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

import javax.ejb.Remote;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Remote
public interface SignProxySessionRemote {

    byte[] signPayload(byte[] data, final int signingCaId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CADoesntExistsException, SignRequestSignatureException;
}
