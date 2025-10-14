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
package org.ejbca.core.protocol.scep;

import jakarta.ejb.Local;
import jakarta.ejb.Timer;
import jakarta.transaction.SystemException;

@Local
public interface ScepKeyRenewalSessionLocal extends ScepKeyRenewalSession {

	/**
	 * Activate the job with default intervals.
	 */
	void start();

	/**
	 * Cancel all existing timers for the job.
	 */
	void stop();

	/**
	 * Restart all the timers for the job.
	 * Uses the configured or default schedule.
	 */
	void restart();

	/**
	 * Run the job after timer runs out.
	 * @param timer EJB Timer
	 */
	void timeoutHandler(final Timer timer) throws SystemException;

	/**
	 * Check if the job has active timers.
	 * @return boolean
	 */
	boolean hasTimers();

}
