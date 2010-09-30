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

import org.ejbca.core.model.log.LogConfiguration;

/**
 * Local interface for LogSession.
 */
@Local
public interface LogSessionLocal extends LogSession {
	
    /**
     * Saves the log configuration to the database without logging.
     * Should only be used from loadLogConfiguration(..)
     * @param logConfiguration the logconfiguration to save.
     */
	public void saveNewLogConfiguration(int caid, LogConfiguration logConfiguration);
}
