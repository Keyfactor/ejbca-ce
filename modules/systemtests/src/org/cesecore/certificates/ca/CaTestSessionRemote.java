/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * CRUD bean for creating, removing and retrieving CAs.
 * 
 * Based on EJBCA version: CaSession.java 10428 2010-11-11 16:45:12Z anatom
 * Based on EJBCA version: CaSessionRemote.java 10428 2010-11-11 16:45:12Z anatom
 * 
 * @version $Id: CaTestSessionRemote.java 841 2011-05-19 14:14:29Z johane $
 */
@Remote
public interface CaTestSessionRemote {

    /** @see org.cesecore.certificates.ca.CaSessionLocal#getCA(AuthenticationToken, int) */
    public CA getCA(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException;
  
    /** @see org.cesecore.certificates.ca.CaSessionLocal#getCA(AuthenticationToken, String) */
    public CA getCA(AuthenticationToken admin, String name) throws CADoesntExistsException, AuthorizationDeniedException;
}
