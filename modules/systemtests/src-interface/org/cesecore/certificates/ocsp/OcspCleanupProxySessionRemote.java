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
     * Check if the caller has active timers.
     *
     * @param callerName name of the class that starts job
     * @return boolean
     */
    boolean hasTimers(String callerName);
}
