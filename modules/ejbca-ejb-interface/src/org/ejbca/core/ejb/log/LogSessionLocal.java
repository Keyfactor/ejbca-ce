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
package org.ejbca.core.ejb.log;

import javax.ejb.Local;

/**
 * Local interface for LogSession.
 */
@Local
public interface LogSessionLocal extends LogSession {

    /**
     * Internal implementation for logging. DO NOT USE! ONLY PUBLIC FOR INTERNAL
     * LOG-IMPLEMENTATION TO START A NEW TRANSACTION..
     */
    public void doSyncronizedLog(org.ejbca.core.model.log.ILogDevice dev, org.ejbca.core.model.log.Admin admin, int caid, int module, java.util.Date time,
            java.lang.String username, java.security.cert.Certificate certificate, int event, java.lang.String comment, java.lang.Exception ex);

}
