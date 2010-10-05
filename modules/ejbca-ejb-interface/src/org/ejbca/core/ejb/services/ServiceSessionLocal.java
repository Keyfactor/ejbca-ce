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
package org.ejbca.core.ejb.services;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.ejb.Local;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.IWorker;

/**
 * Local interface for ServiceSession.
 */
@Local
public interface ServiceSessionLocal extends ServiceSession {

    /**
     * Method creating a hashmap mapping service id (Integer) to service name
     * (String).
     */
    public HashMap<Integer, String> getServiceIdToNameMap(Admin admin);

	public Map<Integer, Long> getNewServiceTimeouts(HashSet<Serializable> existingTimers);
   
	public long getServiceInterval(Integer serviceId);

	public IWorker getWorkerIfItShouldRun(Integer timerInfo, long nextTimeout);

	public void executeServiceInTransaction(IWorker worker, String serviceName);
	
	public void cancelTimer(Integer id);
}
