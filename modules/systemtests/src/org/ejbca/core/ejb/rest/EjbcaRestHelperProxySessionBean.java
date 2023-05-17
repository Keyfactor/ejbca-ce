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
import org.cesecore.jndi.JndiConstants;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import java.security.cert.X509Certificate;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaRestHelperProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaRestHelperProxySessionBean implements EjbcaRestHelperProxySessionRemote {
    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSessionLocal;

    @Override
    public AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException {
        return ejbcaRestHelperSessionLocal.getAdmin(allowNonAdmins, cert, oauthBearerToken, false);
    }
}
