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
package org.ejbca.core.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

/**
 * JEE5 EJB lookup helper.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EnterpriseEditionEjbBridgeSessionBean implements EnterpriseEditionEjbBridgeSessionLocal {

    @Override
    public <T> T getEnterpriseEditionEjbLocal(Class<T> localInterfaceClass, String modulename) {
        return null; // NOOP in community edition
    }
    
    @Override
    public boolean isRunningEnterprise() {
        return false;
    }

    @Override
    public void clearEnterpriseAuthorizationCaches() {
        // NOOP in community edition
    }
}
