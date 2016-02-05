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
 * Class Holding cache variable for CESeCore global configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * 
 * @version $Id$
 *
 */
public class GlobalCesecoreConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the global configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalCesecoreConfiguration globalconfigurationCache = null;
    /** help variable used to control that GlobalConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  
    
    public GlobalCesecoreConfigurationCache() {
    }

    @Override
    public String getConfigId() {
        return GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID;
    }

    @Override
    public void clearCache() {
        globalconfigurationCache = null;

    }

    @Override
    public void saveData() {
        globalconfigurationCache.saveData();
    }

    @Override
    public boolean needsUpdate() {
        if (globalconfigurationCache != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return globalconfigurationCache;

    }

    @Override
    public ConfigurationBase getConfiguration(@SuppressWarnings("rawtypes") HashMap data) {
        ConfigurationBase returnval = new GlobalCesecoreConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new GlobalCesecoreConfiguration();      

    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
        this.globalconfigurationCache = (GlobalCesecoreConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
    }

    @Override
    public Properties getAllProperties() {
        return ConfigurationHolder.getAsProperties();
    }

}
