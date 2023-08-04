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
package org.ejbca.core.protocol.est;

import java.security.cert.X509Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

@Local
public interface EstOperationsSessionLocal extends EstOperationsSession {

    /**
     * Handles an EST request.
     *
     * @param authenticationToken Authentication token of incoming request. Needed to handle domain security of peer connections. May be null for legacy, unauthenticated call.
     * @param operation the EST operation to perform
     * @param alias the requested CA configuration that should handle the request.
     * @param cert The client certificate used to request this operation if any
     * @param username The authentication username if any
     * @param password The authentication password if any
     * @param requestBody The HTTP request body. Usually a PKCS#10
     * @return the HTTP response body
     *
     * @throws NoSuchAliasException if the alias doesn't exist
     * @throws CADoesntExistsException if the CA specified in a request for CA certs doesn't exist
     * @throws CertificateCreateException if an error was encountered when trying to enroll
     * @throws CertificateRenewalException if an error was encountered when trying to re-enroll
     * @throws AuthenticationFailedException if request was sent in without an authenticating certificate, or the username/password combo was 
     *           invalid (depending on authentication method). 
     * @throws AuthorizationDeniedException if the supplied authenticationToken did not have access to the configured CA in the EST alias
     */
    byte[] dispatchRequest(AuthenticationToken authenticationToken, String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException, AuthorizationDeniedException;
}
