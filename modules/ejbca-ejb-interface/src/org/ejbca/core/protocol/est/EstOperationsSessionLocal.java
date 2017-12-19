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
     * @throws NoSuchAliasException
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws CertificateProfileDoesNotExistException
     * @throws NoSuchAlgorithmException
     */
    byte[] dispatchRequest(String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException, CertificateProfileDoesNotExistException,
            NoSuchAlgorithmException;
}
