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
package org.ejbca.core.ejb.ws;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

import jakarta.ejb.Remote;
import java.security.cert.X509Certificate;

@Remote
public interface EjbcaWSHelperProxySessionRemote {

    /**
     * Gets an AuthenticationToken object for a WS-API administrator authenticated with the given client certificate or
     * OAuth token. If both provided, X509 certificate will be used.
     *
     * - Checks (through authenticationSession.authenticate) that the certificate is valid if certificate is used.
     * - If (WebConfiguration.getRequireAdminCertificateInDatabase) checks (through authenticationSession.authenticate) that the admin certificate is not revoked.
     * - If (allowNonAdmin == false), checks that the admin have access to /administrator, i.e. really is an administrator with the certificate mapped in an admin role.
     *   Does not check any other authorization though, other than that it is an administrator.
     *
     * @param cert The X.509 client certificate.
     * @param oauthBearerToken OAuth token for JWT authentication
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins == false and the cert does not belong to an admin
     */
    AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException;
}
