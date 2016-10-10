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

package org.ejbca.core.ejb.services;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;

/**
 * Some test methods that are used from system tests
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ServiceTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceTestSessionBean implements ServiceTestSessionRemote {

    @EJB
    private ServiceSessionLocal serviceSession;
    
    @Override
    public boolean getWorkerIfItShouldRun(Integer timerInfo, long nextTimeout, boolean testRunOnOtherNode) {
        return serviceSession.getWorkerIfItShouldRun(timerInfo, nextTimeout, testRunOnOtherNode) != null;
    }

}
