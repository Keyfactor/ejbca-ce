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
package org.cesecore.configuration;

import java.util.HashMap;
import java.util.Properties;

/**
 * Marker interface for classes that want to be treated as contents of the Global Configuration Cache
 * 
 * @version $Id$
 *
 */
public interface ConfigurationCache {

    String getConfigId();
    
    void clearCache();
    
    void saveData();
    
    boolean needsUpdate();
    
    ConfigurationBase getConfiguration();
    
    @SuppressWarnings("rawtypes")
    ConfigurationBase getConfiguration(final HashMap data);
    
    ConfigurationBase getNewConfiguration();
    
    void updateConfiguration(ConfigurationBase configuration);
    
    Properties getAllProperties();
    
}
