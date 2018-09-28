/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocool.acme;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionProxyRemote;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAuthorizationDataSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeAuthorizationDataSessionProxyBean implements AcmeAuthorizationDataSessionProxyRemote {

    @EJB
    private AcmeAuthorizationDataSessionLocal acmeAuthorizationDataSessionLocal;

    @Override
    public String createOrUpdate(AcmeAuthorization acmeAuthorization) {
        return acmeAuthorizationDataSessionLocal.createOrUpdate(acmeAuthorization);
    }

    @Override
    public void remove(String authorizationId) {
        acmeAuthorizationDataSessionLocal.remove(authorizationId);
    }
}
