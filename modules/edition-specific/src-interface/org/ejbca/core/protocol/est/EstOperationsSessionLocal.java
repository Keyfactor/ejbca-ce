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

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;

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
     * @throws UnsupportedOperationException if the method is not available in this edition of EJBCA
     * @throws NoSuchAliasException If the requested EST alias doesn't exist
     * @throws CADoesntExistsException If the request CA for the given alias doesn't exist
     * @throws AuthorizationDeniedException If the user it unauthroized to enroll or reenroll
     * @throws CertificateProfileDoesNotExistException
     * @throws NoSuchAlgorithmException
     * @throws AuthenticationFailedException If authentication is required
     */
    byte[] dispatchRequest(String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws UnsupportedOperationException, NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException, CertificateProfileDoesNotExistException,
            NoSuchAlgorithmException, AuthenticationFailedException;
}
