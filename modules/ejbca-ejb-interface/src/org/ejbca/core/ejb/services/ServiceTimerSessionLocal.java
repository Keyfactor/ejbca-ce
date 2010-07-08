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

import javax.ejb.Local;

/**
 * Local interface for ServiceTimerSession.
 */
@Local
public interface ServiceTimerSessionLocal extends ServiceTimerSession {
    /**
     * Internal method should not be called from external classes, method is
     * public to get automatic transaction handling. This method need
     * "RequiresNew" transaction handling, because we want to make sure that the
     * timer runs the next time even if the execution fails.
     * 
     * @return true if the service should run, false if the service should not
     *         run
     */
    public boolean checkAndUpdateServiceTimeout(long nextInterval, int timerInfo, org.ejbca.core.model.services.ServiceConfiguration serviceData,
            java.lang.String serviceName);

  

}
