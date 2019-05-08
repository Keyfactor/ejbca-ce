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
package org.ejbca.core.ejb.config;

import java.util.Properties;

import javax.ejb.Remote;

/**
 * @version $Id$
 */
@Remote
public interface ConfigurationSessionRemote {

	/**
     * Try to backup the current configuration.
     * @return false if a backup already exists.
     */
    boolean backupConfiguration();

    /**
     * Restore configuration from backup.
     * @return false if no backup exists.
     */
    boolean restoreConfiguration();

    /**
     * Makes sure there is a backup of the configuration and then alters the
     * active configuration with all the properties.
     */
    boolean updateProperties(Properties properties);

    /**
     * Makes sure there is a backup of the configuration and then alters the
     * active configuration with the property.
     */
    boolean updateProperty(String key, String value);
    
    boolean updateCesecoreProperty(String key, String value);

    /** Verifies that the property is set to the expected value. */
    boolean verifyProperty(String key, String value);

    /** Returns a property from the current server configuration. */
    String getProperty(String key);
    
    /** Returns a property from the current server configuration. */
    String getCesecoreProperty(String key);

    /** @return all currently used properties */
    Properties getAllProperties();
}
