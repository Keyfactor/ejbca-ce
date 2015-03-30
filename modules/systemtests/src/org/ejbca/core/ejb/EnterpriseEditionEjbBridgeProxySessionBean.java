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
package org.ejbca.core.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;

/**
 * @see EnterpriseEditionEjbBridgeProxySessionRemote
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EnterpriseEditionEjbBridgeProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EnterpriseEditionEjbBridgeProxySessionBean implements EnterpriseEditionEjbBridgeProxySessionRemote {

    @EJB
    private EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession;

    @Override
    public boolean isRunningEnterprise() {
        return enterpriseEditionEjbBridgeSession.isRunningEnterprise();
    }

}