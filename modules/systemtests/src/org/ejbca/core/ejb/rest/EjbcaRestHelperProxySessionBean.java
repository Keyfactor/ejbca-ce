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
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import java.security.cert.X509Certificate;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaRestHelperProxySessionBean implements EjbcaRestHelperProxySessionRemote {
    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;

    @Override
    public AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException {
        return ejbcaRestHelperSessionLocal.getAdmin(allowNonAdmins, cert, oauthBearerToken, false);
    }
}
