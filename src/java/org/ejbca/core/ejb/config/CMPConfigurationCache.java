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
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class Holding cache variable for cmp configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id$
 */
public final class CMPConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the cmp configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile CmpConfiguration cmpconfigurationCache = null;
    /** help variable used to control that CmpConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

    public CMPConfigurationCache() {
        // Do nothing
    }


    @Override
    public boolean needsUpdate() {
        if (cmpconfigurationCache != null && lastupdatetime + EjbcaConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }
    
    public void clearCache() {
        cmpconfigurationCache = null;
    }

    @Override
    public String getConfigId() {
        return CmpConfiguration.CMP_CONFIGURATION_ID;
    }

    @Override
    public void saveData() {
       cmpconfigurationCache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return cmpconfigurationCache;
    }
    
    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new CmpConfiguration();
        returnval.loadData(data);
        return returnval;
    }


    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        this.cmpconfigurationCache = (CmpConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
        
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new CmpConfiguration();      
    }


    @Override
    public Properties getAllProperties() {
        return cmpconfigurationCache.getAsProperties();
    }
}
