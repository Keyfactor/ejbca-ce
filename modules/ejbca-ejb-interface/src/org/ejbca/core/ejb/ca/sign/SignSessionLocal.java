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
package org.ejbca.core.ejb.ca.sign;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.request.RequestMessage;

/**
 * Local interface for RSASignSession.
 */
@Local
public interface SignSessionLocal extends SignSession {
    /**
     * Returns a CA that a request is targeted for. Uses different methods in priority order to try to find it.
     * 
     * @param admin an authenticating token
     * @param req the request
     * @param doLog if this operation should log in the audit log.
     * @return CA object
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     */
    CA getCAFromRequest(AuthenticationToken admin, RequestMessage req, boolean doLog) throws CADoesntExistsException, AuthorizationDeniedException;

}
