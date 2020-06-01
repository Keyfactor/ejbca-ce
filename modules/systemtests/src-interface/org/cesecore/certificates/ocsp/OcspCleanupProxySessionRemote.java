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
package org.cesecore.certificates.ocsp;

import javax.ejb.Remote;
import javax.ejb.ScheduleExpression;

/**
 * @version $Id$
 */
@Remote
public interface OcspCleanupProxySessionRemote {
    /**
     * Activate the Ocsp response cleanup job with default intervals.
     */
    void start();

    /**
     * Activate the Ocsp response cleanup job with specific intervals.
     *
     * @param expression interval for running the cleanup job
     */
    void start(ScheduleExpression expression);

    /**
     * Cancel all existing timers for Ocsp response cleanup.
     */
    void stop();

    /**
     * Restart all the timers for the cleanup job.
     *
     * Uses the configured schedule.
     */
    void restart();

    /**
     * Check if the caller has active timers.
     *
     * @return boolean
     */
    boolean hasTimers();
}
