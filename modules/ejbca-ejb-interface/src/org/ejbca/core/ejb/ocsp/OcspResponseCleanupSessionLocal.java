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
package org.ejbca.core.ejb.ocsp;

import javax.ejb.Local;
import javax.ejb.ScheduleExpression;
import javax.ejb.Timer;

/**
 * Local interface for OcspResponseCleanupSession
 *
 * @version $Id$
 */
@Local
public interface OcspResponseCleanupSessionLocal extends OcspResponseCleanupSession {

    /**
     * Activate the Ocsp response cleanup job with default intervals.
     */
    void start();

    /**
     * Activate the Ocsp response cleanup job with specific intervals.
     *
     * @param expression interval for running the clean up job
     */
    void start(ScheduleExpression expression);

    /**
     * Cancel all existing timers for Ocsp response cleanup.
     */
    void stop();

    /**
     * Restart all the timers for the cleanup job.
     *
     * Uses the configured or default schedule.
     */
    void restart();

    /**
     * Run the cleanup method after timer runs out.
     *
     * @param timer EJB Timer
     */
    void timeoutHandler(final Timer timer);

    /**
     * Check if the job has active timers.
     *
     * @return boolean
     */
    boolean hasTimers();
}