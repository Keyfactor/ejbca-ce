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
import org.ejbca.config.EstConfiguration;

/**
 * Class Holding cache variable for est configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id: CMPConfigurationCache.java 22740 2016-02-05 13:28:45Z mikekushner $
 */
public final class EstConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the cmp configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile EstConfiguration estconfigurationCache = null;
    /** help variable used to control that CmpConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

    public EstConfigurationCache() {
        // Do nothing
    }


    @Override
    public boolean needsUpdate() {
        if (estconfigurationCache != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }
    
    public void clearCache() {
        estconfigurationCache = null;
    }

    @Override
    public String getConfigId() {
        return EstConfiguration.EST_CONFIGURATION_ID;
    }

    @Override
    public void saveData() {
       estconfigurationCache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return estconfigurationCache;
    }
    
    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new EstConfiguration();
        returnval.loadData(data);
        return returnval;
    }


    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        this.estconfigurationCache = (EstConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
        
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new EstConfiguration();      
    }


    @Override
    public Properties getAllProperties() {
        return estconfigurationCache.getAsProperties();
    }
}
