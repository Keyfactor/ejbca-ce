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

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;

import java.util.HashMap;
import java.util.Properties;

public class GlobalEndEntityProfileConfigurationCache implements ConfigurationCache {

    private volatile GlobalEndEntityProfileConfiguration globalEEPConfiguration = null;
    private volatile long lastupdatetime = -1;

    public GlobalEndEntityProfileConfigurationCache() {
        // Do nothing
    }

    @Override
    public String getConfigId() {
        return GlobalEndEntityProfileConfiguration.EEP_CONFIGURATION_ID;
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return globalEEPConfiguration;
    }

    @Override
    public ConfigurationBase getConfiguration(@SuppressWarnings("rawtypes") HashMap data) {
        ConfigurationBase returnval = new GlobalEndEntityProfileConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new GlobalEndEntityProfileConfiguration();
    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
        this.globalEEPConfiguration = (GlobalEndEntityProfileConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
    }

    @Override
    public void saveData() {
        globalEEPConfiguration.saveData();

    }

    @Override
    public void clearCache() {
        globalEEPConfiguration = null;
    }

    @Override
    public boolean needsUpdate() {
        return globalEEPConfiguration == null || lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() <= System.currentTimeMillis();
    }

    @Override
    public Properties getAllProperties() {
        return ConfigurationHolder.getAsProperties();
    }
}
