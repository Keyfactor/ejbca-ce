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

import javax.ejb.Remote;
import java.security.cert.X509Certificate;

@Remote
public interface EjbcaRestHelperProxySessionRemote {
    AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException;
}
