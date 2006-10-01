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
package org.ejbca.core.model.services;

/**
 * The worker interface of a service. It is the main class of a service.
 * A worker has one IInterval and one IAction.
 * 
 * The methods work() method is used to signal to this service that
 * it is time to work.
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: IWorker.java,v 1.2 2006-10-01 17:46:25 herrvendil Exp $
 */
public interface IWorker {

	/**
	 * Method that configures this worker and also sets up it's action and interval.
	 * 
	 * @param serviceConfiguration
	 * @param serviceName
	 */
	public void init(ServiceConfiguration serviceConfiguration, String serviceName);
	
	/**
	 * The main method that is called by the TimeSessionBean each time
	 * it is time to activate this service
	 *
	 */
	public void work() throws ServiceExecutionFailedException;
	
	/**
	 * 
	 * @return the time in seconds to next execution.
	 */
	public long getNextInterval();
	
}
