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
package org.cesecore.config;

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;

/**
 * Needed because EJB spec does not allow volatile, non-final fields in session beans.
 */
public class GlobalCaConfigurationCache implements ConfigurationCache {

    private volatile GlobalCaConfiguration globalCaConfiguration = null;
    private volatile long lastupdatetime = -1;  
    
    @Override
    public String getConfigId() {
        return GlobalCaConfiguration.CA_CONFIGURATION_ID;
    }

    @Override
    public void clearCache() {
        globalCaConfiguration = null;

    }

    @Override
    public void saveData() {
       globalCaConfiguration.saveData();

    }

    @Override
    public boolean needsUpdate() {
        return globalCaConfiguration == null || lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() <= System.currentTimeMillis();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return globalCaConfiguration;
    }

    @Override
    public ConfigurationBase getConfiguration(@SuppressWarnings("rawtypes") HashMap data) {
        ConfigurationBase returnval = new GlobalCaConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new GlobalCaConfiguration();
    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
        this.globalCaConfiguration = (GlobalCaConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();

    }

    @Override
    public Properties getAllProperties() {
        return ConfigurationHolder.getAsProperties();
    }

}
