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
     * Activate the Ocsp response clean-up job with default intervals.
     *
     * @param callerName name of the class that starts job
     */
    void start(String callerName);

    /**
     * Activate the Ocsp response clean-up job with specific intervals.
     *
     * @param callerName name of the class that starts job
     * @param expression interval for running the clean up job
     */
    void start(String callerName, ScheduleExpression expression);

    /**
     * Cancel all existing timers for Ocsp response clean-up.
     *
     * @param callerName name of the class that starts job
     */
    void stop(String callerName);

    /**
     * Run the clean-up method after timer runs out.
     *
     * @param timer EJB Timer
     */
    void timeoutHandler(final Timer timer);

    /**
     * Check if the caller has active timers.
     *
     * @param callerName name of the class that starts job
     * @return boolean
     */
    boolean hasTimers(String callerName);
}