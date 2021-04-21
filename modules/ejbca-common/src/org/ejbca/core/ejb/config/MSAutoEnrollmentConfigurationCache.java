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
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.MSAutoEnrollmentConfiguration;

import java.util.HashMap;
import java.util.Properties;

public class MSAutoEnrollmentConfigurationCache implements ConfigurationCache {

    private volatile MSAutoEnrollmentConfiguration cache = null;
    private volatile long lastUpdateTime = -1;

    @Override
    public boolean needsUpdate() {
        return cache==null || lastUpdateTime + CesecoreConfiguration.getCacheGlobalConfigurationTime() < System.currentTimeMillis();
    }

    @Override
    public void clearCache() {
        cache = null;
    }

    @Override
    public String getConfigId() {
        if (cache==null) {
            return getNewConfiguration().getConfigurationId();
        }
        return cache.getConfigurationId();
    }

    @Override
    public void saveData() {
        cache.saveData();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return cache;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public ConfigurationBase getConfiguration(final HashMap data) {
        final ConfigurationBase returnval = getNewConfiguration();
        returnval.loadData(data);
        return returnval;
    }

    @Override
    public void updateConfiguration(final ConfigurationBase configuration) {
        cache = (MSAutoEnrollmentConfiguration) configuration;
        lastUpdateTime = System.currentTimeMillis();
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new MSAutoEnrollmentConfiguration();
    }

    @Override
    public Properties getAllProperties() {
        return null;
    }
}
