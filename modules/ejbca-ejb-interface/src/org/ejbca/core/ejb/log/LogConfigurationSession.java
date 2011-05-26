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

import org.ejbca.core.model.log.LogConfiguration;

/**
 * Interface for interactions with LogConfigurationData.
 * @version $Id$
 */
public interface LogConfigurationSession {

    /**
     * Loads the log configuration from the database.
     * @return the LogConfiguration or a new default LogConfiguration if no such configuration exists
     */
    LogConfiguration loadLogConfiguration(int caid);

    /** Do not use unless updates without audit log are intentional. Save a logConfiguration. Updates or creates new row in database. */
    void saveLogConfiguration(int caid, LogConfiguration logConfiguration, boolean updateCache);

    /** Clear and reload log profile caches. */
    void flushConfigurationCache();
}
