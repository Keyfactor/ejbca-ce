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
package org.ejbca.core.model.era;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TestRaMasterApiProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class TestRaMasterApiProxySessionBean implements TestRaMasterApiProxySessionRemote {

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    
    @Override
    public byte[] cmpDispatch(byte[] pkiMessageBytes, String cmpConfigurationAlias)
            throws NoSuchAliasException {
        AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("TestRaMasterApiProxySessionBean");
        return raMasterApiProxyBean.cmpDispatch(authenticationToken, pkiMessageBytes, cmpConfigurationAlias);
    }

    @Override
    public boolean isBackendAvailable(Class<? extends RaMasterApi> apiType) {
        return raMasterApiProxyBean.isBackendAvailable(apiType);
    }

}
