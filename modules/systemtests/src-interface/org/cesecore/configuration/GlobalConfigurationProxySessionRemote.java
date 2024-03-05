/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.configuration;

import javax.ejb.Remote;

/**
 */
@Remote
public interface GlobalConfigurationProxySessionRemote extends GlobalConfigurationSessionLocal {

    /**
     * Adds a configuration to the database without going through the caches in GlobalConfigurationSession
     * 
     * @param configurationBase a configuration
     */
    void addConfiguration(ConfigurationBase configurationBase);
}
