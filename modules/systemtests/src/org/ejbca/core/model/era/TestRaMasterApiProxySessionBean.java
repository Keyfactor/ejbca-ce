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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

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

    @Override
    public byte[] createCertificateWS(AuthenticationToken authenticationToken, UserDataVOWS userdata, String requestData, int requestType,
            String hardTokenSN, String responseType)
            throws AuthorizationDeniedException, ApprovalException, EjbcaException, EndEntityProfileValidationException {
        return raMasterApiProxyBean.createCertificateWS(authenticationToken, userdata, requestData, requestType, hardTokenSN, responseType);
    }

    @Override
    public boolean addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        return raMasterApiProxyBean.addUser(authenticationToken, endEntity, clearpwd);
    }

}
