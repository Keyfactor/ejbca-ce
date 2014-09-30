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

import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * The worker interface of a service. It is the main class of a service.
 * A worker has one IInterval and one IAction.
 * 
 * The methods work() method is used to signal to this service that
 * it is time to work.
 *
 * @version $Id$
 */
public interface IWorker {

	/** Should be a ';' separated string of CAIds. */
	public static final String PROP_CAIDSTOCHECK     = "worker.caidstocheck";
	public static final String PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK     = "worker.certificateprofileidstocheck";
	
	/** The time in 'timeunit' that a user is allowed to have status 'new' since last modification date */
	public static final String PROP_TIMEBEFOREEXPIRING = "worker.timebeforeexpiring";
	
	/** Unit in days, hours or seconds */
	public static final String PROP_TIMEUNIT           = "worker.timeunit";

	public static final String UNIT_SECONDS = "SECONDS";
	public static final String UNIT_MINUTES = "MINUTES";
	public static final String UNIT_HOURS = "HOURS";
	public static final String UNIT_DAYS = "DAYS";
	
	public static final int UNITVAL_SECONDS = 1;
	public static final int UNITVAL_MINUTES = 60;
	public static final int UNITVAL_HOURS = 3600;
	public static final int UNITVAL_DAYS = 86400;

	public static final String[] AVAILABLE_UNITS = {UNIT_SECONDS, UNIT_MINUTES, UNIT_HOURS, UNIT_DAYS};
	public static final int[] AVAILABLE_UNITSVALUES = {UNITVAL_SECONDS, UNITVAL_MINUTES, UNITVAL_HOURS, UNITVAL_DAYS};

	/**
	 * Method that configures this worker and also sets up it's action and interval.
	 * 
	 * @param serviceConfiguration
	 * @param serviceName
	 */
	public void init(AuthenticationToken admin, ServiceConfiguration serviceConfiguration, String serviceName, long runTimeStamp, long nextRunTimeStamp);
	
	/**
	 * The main method that is called by the TimeSessionBean each time
	 * it is time to activate this service
	 * @param ejbs A map between Local EJB interface classes and their injected stub
	 */
	public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException;
	
	/**
	 * 
	 * @return the time in seconds to next execution.
	 */
	public long getNextInterval();
}
