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
package org.ejbca.core.ejb.rest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

import jakarta.ejb.Remote;
import java.security.cert.X509Certificate;

@Remote
public interface EjbcaRestHelperProxySessionRemote {

    /**
     * Gets an AuthenticationToken object authenticated with the given X509 certificate or OAuth token. If both provided,
     * X509 certificate will be used.
     *
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @param cert X509 certificate
     * @param oauthBearerToken OAuth token for JWT authentication
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins = false and the certificate does not belong to an administrator
     */
    AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException;
}
