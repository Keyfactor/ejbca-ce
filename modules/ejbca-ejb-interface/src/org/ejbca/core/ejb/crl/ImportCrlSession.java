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
package org.ejbca.core.ejb.crl;

import java.security.cert.CRLException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;

public interface ImportCrlSession {

    /**
     * Method used to import a CRL to the database if it is newer than any CRL it already has
     * 
     * @param authenticationToken The administrator performing the operation
     * @param cainfo of the CA that issued the CRL
     * @param crlbytes the CRL in bytes
     * @throws CrlImportException If a problem occurs when processing the imported CRL
     * @throws CrlStoreException If a problem occurs when adding the imported CRL to the database
     * @throws CRLException If a problem occurs when parsing the CRL
     * @throws AuthorizationDeniedException If the administrator is not authorized to perform the required operations
     */
    void importCrl(final AuthenticationToken authenticationToken, final CAInfo cainfo, final byte[] crlbytes) 
            throws CrlImportException, CrlStoreException, CRLException, AuthorizationDeniedException;
}
