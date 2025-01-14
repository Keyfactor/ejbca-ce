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
package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportRequestData;
import org.cesecore.keys.keyimport.KeyImportResponseData;
import org.ejbca.core.EjbcaException;

import java.util.List;

/**
 *
 */
public interface KeyImportSession {

    /**
     * Imports keys to EJBCA.
     *
     * @param authenticationToken authentication token
     * @param keyImportRequestData data required to perform the key imports
     * @return the list of failed key imports as well as a general error if it does exist
     */
    KeyImportResponseData importKeys(AuthenticationToken authenticationToken, KeyImportRequestData keyImportRequestData)
            throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException;
}
