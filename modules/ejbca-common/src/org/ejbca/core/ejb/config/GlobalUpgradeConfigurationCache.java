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

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Cache of upgrade configuration.
 * 
 * @version $Id$
 */
public class GlobalUpgradeConfigurationCache implements ConfigurationCache {

    /**
     * This cache may be unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalUpgradeConfiguration configurationCache = null;
    /** help variable used to control that update isn't performed to often. */
    private volatile long lastupdatetime = -1;  
    
    public GlobalUpgradeConfigurationCache() {}

    @Override
    public boolean needsUpdate() {
        if (configurationCache != null && lastupdatetime + EjbcaConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }

    public void clearCache() {
        configurationCache = null;
    }

    @Override
    public String getConfigId() {
        return GlobalUpgradeConfiguration.CONFIGURATION_ID;
    }

    @Override
    public void saveData() {
       configurationCache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return configurationCache;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new GlobalUpgradeConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        this.configurationCache = (GlobalUpgradeConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
        
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new GlobalUpgradeConfiguration();      
    }

    @Override
    public Properties getAllProperties() {
        return configurationCache.getAsProperties();
    }
}
