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
package org.ejbca.core.model.services;

import java.util.Properties;

/**
 * Class representing an interval to when the service should run next time
 * 
 * It's man method is getTimeToExecution 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public interface IInterval {
	
	/**
	 * Constant indicating if the service should stop executing
	 */
	public static final long DONT_EXECUTE = -1;
	
	/**
	 * Method that should initialize the interval according to the 
	 * configured properties.
	 * 
	 * This method should be called before the any action calls are made.
	 */
	public void init(Properties properties, String serviceName);
	
	/**
	 * @return the time in seconds to next execution or DONT_EXECUTE if the
	 * service should run anymore
	 */
	public long getTimeToExecution();

}
