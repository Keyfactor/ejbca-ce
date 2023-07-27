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

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.EABConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;

import java.util.HashMap;
import java.util.Properties;

/**
 * Class Holding cache variable for custom eab configuration. Needed because EJB spec does not allow volatile, non-final
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, the using class must ensure that it does not try to use a null value.
 * Only the method "needsUpdate will return true of the cache variable is null.
 *
 */
public class EABConfigurationCache implements ConfigurationCache {
    /**
     * Cache variable containing the custom oauth configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile EABConfiguration eabConfiguration = null;

    private volatile long lastupdatetime = -1;

    @Override
    public String getConfigId() {
        return EABConfiguration.EAB_CONFIGURATION_ID;
    }

    @Override
    public void clearCache() {
        eabConfiguration = null;
    }

    @Override
    public void saveData() {
        eabConfiguration.saveData();
    }

    @Override
    public boolean needsUpdate() {
        if (eabConfiguration != null && lastupdatetime + CesecoreConfiguration.getCacheGlobalConfigurationTime() > System.currentTimeMillis()) {
            return false;
        }
        return true;
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return eabConfiguration;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public ConfigurationBase getConfiguration(HashMap data) {
        ConfigurationBase returnval = new EABConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new EABConfiguration();
    }

    @Override
    public void updateConfiguration(ConfigurationBase configuration) {
        this.eabConfiguration = (EABConfiguration) configuration;
        lastupdatetime = System.currentTimeMillis();
    }

    @Override
    public Properties getAllProperties() {
        return null;
    }
}
