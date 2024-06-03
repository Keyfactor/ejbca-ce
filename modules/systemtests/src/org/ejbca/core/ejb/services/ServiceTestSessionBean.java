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

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;


/**
 * Some test methods that are used from system tests
 * 
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceTestSessionBean implements ServiceTestSessionRemote {

    @EJB
    private ServiceSessionLocal serviceSession;
    
    @Override
    public boolean getWorkerIfItShouldRun(Integer timerInfo, long nextTimeout, boolean testRunOnOtherNode) {
        return serviceSession.getWorkerIfItShouldRun(timerInfo, nextTimeout, testRunOnOtherNode) != null;
    }

}
