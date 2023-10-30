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

import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;

import javax.ejb.Local;
import javax.ejb.Timer;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Local interface for ServiceSession.
 * @version $Id$
 */
@Local
public interface ServiceSessionLocal extends ServiceSession {

    /** @return HashMap mapping service id (Integer) to service name (String). */
    HashMap<Integer, String> getServiceIdToNameMap();

    /**
     * Internal method used from load() to separate timer access from database
     * access transactions.
     */
	Map<Integer, Long> getNewServiceTimeouts(final HashSet<Serializable> existingTimers);
   
    /**
     * Return the configured interval for the specified worker or
     * IInterval.DONT_EXECUTE if it could not be found.
     */
	long getServiceInterval(final Integer serviceId);
 
	   /**
     * Returns worker regardless of service configurations.
     * Timestamps, apart from the runeTimeStamp, are not updated.
     * @param serviceId the ID of the service to check
     * @param nextTimeout the next time the service should run, in this case now.
     * @return IWorker if it can run, null otherwise
     */
    IWorker getWorkerAndRunService(final Integer serviceId, final long nextTimeout);
    
	/**
     * Reads the current timeStamp values and tries to update them in a single transaction.
     * If the database commit is successful the method returns the worker, otherwise null.
     * Could throw a runtime exception if there are database errors, so these should be caught.
     * 
     * Should only be called from timeoutHandler
     * @param serviceId the ID of the service to check
     * @param nextTimeout the next time the service should run
     * @return IWorker if it should run, null otherwise
     */
	IWorker getWorkerIfItShouldRun(final Integer serviceId, final long nextTimeout);

	/** As above but used to JUnit testing to be able to "fake" that the service was running on another node 
	 * Should only be used for testing the logic 
	 * @param testRunOnOtherNode set to true to force the service to believe it has been running on another node
	 * @see #getWorkerIfItShouldRun(Integer, long)
	 */
    IWorker getWorkerIfItShouldRun(Integer serviceId, long nextTimeout, boolean testRunOnOtherNode);

	/** Executes a the service in a separate in no transaction. */
	void executeServiceInNoTransaction(final IWorker worker, final String serviceName);
	
	/** Executes a the service in a separate in no transaction or throws exception if fail.
	 *  @param worker the worker
	 *  @param serviceName name of the service to run
	 *  @return ServiceExecutionResult containing result of the execution
	 *  @throws ServiceExecutionFailedExeption if execution failed 
	 */
	ServiceExecutionResult executeServiceInNoTransactionOrThrowException(IWorker worker, String serviceName) throws ServiceExecutionFailedException;
	
    /** Cancels a timer with the given Id. */
	void cancelTimer(final Integer id);
	
	/** The timeout method */
    void timeoutHandler(final Timer timer);
    
    /**
     * Performs a basic diagnostic on the worker to verify if it's runnable in the server's current state
     * 
     * @param worker the worker
     * @return true if the service can run
     */
    boolean canWorkerRun(final IWorker worker);

	/**
	 * Schedule a service with the given service ID for immediate execution.
	 *
	 * @param serviceId the ID of the service
	 */
	void runService(int serviceId);
	
    /**
     * Run a service with the given service ID regardless of it being active or not.
     *
     * @param serviceId the ID of the service
     */
    void runServiceNoTimer (int serviceId) throws ServiceExecutionFailedException;
   
}
