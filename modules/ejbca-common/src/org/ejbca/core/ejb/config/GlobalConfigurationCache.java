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
import java.util.Iterator;
import java.util.Properties;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.config.GlobalConfiguration;

/**
 * Class Holding cache variable for global configuration. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value. 
 * Only the method "needsUpdate will return true of the cache variable is null. 
 * 
 * @version $Id$
 */
public final class GlobalConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the global configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalConfiguration globalconfigurationCache = null;
    /** help variable used to control that GlobalConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

	public GlobalConfigurationCache() {
		// Do nothing
	}


	@Override
	public boolean needsUpdate() {
        if (globalconfigurationCache != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
        	return false;
        }
        return true;
	}
	
	public void clearCache() {
		globalconfigurationCache = null;
	}

    @Override
    public String getConfigId() {
        return GlobalConfiguration.GLOBAL_CONFIGURATION_ID;
    }

    @Override
    public void saveData() {
        globalconfigurationCache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return globalconfigurationCache;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new GlobalConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
      this.globalconfigurationCache = (GlobalConfiguration) configuration;
      lastupdatetime = System.currentTimeMillis();
    }


    @Override
    public ConfigurationBase getNewConfiguration() {
       return new GlobalConfiguration();      
    }


    @Override
    public Properties getAllProperties() {
        Properties ejbca = EjbcaConfigurationHolder.getAsProperties();
        Properties cesecore = ConfigurationHolder.getAsProperties();
        for (Iterator<Object> iterator = ejbca.keySet().iterator(); iterator.hasNext();) {
            String key = (String)iterator.next();
            cesecore.setProperty(key, ejbca.getProperty(key));            
        }
        return cesecore;
    }
}
