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
 * @version $Id$
 */
@Local
public interface ServiceSessionLocal extends ServiceSession {

    /** @return HashMap mapping service id (Integer) to service name (String). */
    public HashMap<Integer, String> getServiceIdToNameMap(Admin admin);

    /**
     * Internal method used from load() to separate timer access from database
     * access transactions.
     */
	public Map<Integer, Long> getNewServiceTimeouts(HashSet<Serializable> existingTimers);
   
    /**
     * Return the configured interval for the specified worker or
     * IInterval.DONT_EXECUTE if it could not be found.
     */
	public long getServiceInterval(Integer serviceId);

    /**
     * Reads the current timeStamp values and tries to update them in a single transaction.
     * If the database commit is successful the method returns the worker, otherwise an
     * exception is thrown.
     * 
     * Should only be called from timeoutHandler
     */
	public IWorker getWorkerIfItShouldRun(Integer timerInfo, long nextTimeout);

	/** Executes a the service in a separate transaction. */
	public void executeServiceInTransaction(IWorker worker, String serviceName);
	
    /** Cancels a timer with the given Id. */
	public void cancelTimer(Integer id);
}
