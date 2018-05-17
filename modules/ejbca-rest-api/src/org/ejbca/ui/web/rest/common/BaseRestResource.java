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

package org.ejbca.ui.web.rest.common;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Base class for common methods used across all REST end points.
 * @version $Id$
 *
 */
public abstract class BaseRestResource {
    
    
    /**
     * Returns an AuthenticationToken for the requesting administrator based on the SSL client certificate
     * @param requestContext HTTP context
     * @param false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @return AuthenticationToken for the requesting administrator
     * @throws AuthorizationDeniedException
     */
    protected AuthenticationToken getAdmin(HttpServletRequest requestContext, boolean allowNonAdmins) throws AuthorizationDeniedException {
        X509Certificate[] certs = (X509Certificate[]) requestContext.getAttribute("javax.servlet.request.X509Certificate");
        if (certs == null || certs[0] == null) {
            throw new AuthorizationDeniedException("Error no client certificate received for authentication.");
        }
        return new EjbLocalHelper().getEjbcaRestHelperSession().getAdmin(allowNonAdmins, certs[0]);
    }
    
}
