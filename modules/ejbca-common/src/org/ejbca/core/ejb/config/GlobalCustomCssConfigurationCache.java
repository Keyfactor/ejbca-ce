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

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.GlobalCustomCssConfiguration;

/**
 * Class Holding cache variable for custom css configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id$
 *
 */
public class GlobalCustomCssConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the custom css configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalCustomCssConfiguration globalCustomCssConfigurationCache = null;
    
    private volatile long lastupdatetime = -1;

    @Override
    public String getConfigId() {
        return GlobalCustomCssConfiguration.CSS_CONFIGURATION_ID;
    }

    @Override
    public void clearCache() {
        globalCustomCssConfigurationCache = null;
        
    }

    @Override
    public void saveData() {
        globalCustomCssConfigurationCache.saveData();
        
    }

    @Override
    public boolean needsUpdate() {
        if (globalCustomCssConfigurationCache != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return globalCustomCssConfigurationCache;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new GlobalCustomCssConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new GlobalCustomCssConfiguration();
    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
        this.globalCustomCssConfigurationCache = (GlobalCustomCssConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
        
    }

    @Override
    public Properties getAllProperties() {
        return null; // Not required
    }  
}