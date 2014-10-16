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
package org.cesecore.certificates.ocsp.cache;

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;

/**
 * Class Holding cache variable for the OCSP configuration
 * 
 * @version $Id$
 */
public final class GlobalOcspConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the ocsp configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile GlobalOcspConfiguration ocspConfigurationCache = null;
    /** help variable used to control that OcspConfiguration update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

    public GlobalOcspConfigurationCache() {
        // Do nothing
    }


    @Override
    public boolean needsUpdate() {
        if (ocspConfigurationCache != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalOcspConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }
    
    public void clearCache() {
        ocspConfigurationCache = null;
    }

    @Override
    public String getConfigId() {
        return GlobalOcspConfiguration.OCSP_CONFIGURATION_ID;
    }

    @Override
    public void saveData() {
       ocspConfigurationCache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return ocspConfigurationCache;
    }
    
    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new GlobalOcspConfiguration();
        returnval.loadData(data);
        return returnval;
    }


    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        this.ocspConfigurationCache = (GlobalOcspConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
        
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new GlobalOcspConfiguration();      
    }


    @Override
    public Properties getAllProperties() {
        throw new UnsupportedOperationException("Not implemented for OCSP cache");
    }
}
