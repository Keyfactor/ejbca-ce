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

import java.util.Set;

import javax.ejb.Local;

/**
 * Local interface for GlobalConfigurationSession.
 * @version $Id$
 */
@Local
public interface GlobalConfigurationSessionLocal extends GlobalConfigurationSession {
    
    /** @return the found entity instance or null if the entity does not exist */
    GlobalConfigurationData findByConfigurationId(String configurationId);
    
    /** Saves the GlobalConfiguration without logging, should be used only for creating an initial configuration.
    *
    * @param globconf the new Configuration
    */
    void saveConfigurationNoLog(ConfigurationBase conf);

    /** @return all registered configuration IDs. */
    Set<String> getIds();
}
