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

import java.security.cert.X509Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * 
 * @version $Id$
 *
 */
@Local
public interface EjbcaRestHelperSessionLocal extends EjbcaRestHelperSession {

    /**
     * @param cert X509 certificate
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins = false and the certificate does not belong to an administrator
     */
    AuthenticationToken getAdmin(boolean allowNonAdmins, X509Certificate cert) throws AuthorizationDeniedException;
    
}
