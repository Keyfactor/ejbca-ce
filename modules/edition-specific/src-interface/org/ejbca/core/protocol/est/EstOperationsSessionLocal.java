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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

/**
 * @version $Id$
 */
@Local
public interface EstOperationsSessionLocal extends EstOperationsSession {

    /**
     * 
     * @param operation
     * @param alias
     * @param cert
     * @param username
     * @param password
     * @param requestBody
     * @return
     * @throws NoSuchAliasException if the alias doesn't exist
     * @throws CADoesntExistsException if the CA specified in a request for CA certs doesn't exist
     * @throws CertificateCreateException if an error was encountered when trying to enroll
     * @throws CertificateRenewalException if an error was encountered when trying to re-enroll
     * @throws AuthenticationFailedException if request was sent in without an authenticating certificate, or the username/password combo was 
     *           invalid (depending on authentication method). 
     */
    byte[] dispatchRequest(String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException;
}
