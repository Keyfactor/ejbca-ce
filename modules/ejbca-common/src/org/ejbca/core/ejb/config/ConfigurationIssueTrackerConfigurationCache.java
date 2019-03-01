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
import org.ejbca.config.IssueCheckerConfiguration;

/**
 * Class holding a cache variable for the EJBCA Configuration Checker configuration.
 *
 * @version $Id$
 */
public class ConfigurationIssueTrackerConfigurationCache implements ConfigurationCache {
    private volatile ConfigurationBase cachedConfiguration;
    private volatile long lastUpdateTime = -1;

    @Override
    public String getConfigId() {
        return cachedConfiguration == null ? getNewConfiguration().getConfigurationId() : cachedConfiguration.getConfigurationId();
    }

    @Override
    public void clearCache() {
        cachedConfiguration = null;
    }

    @Override
    public void saveData() {
        cachedConfiguration.saveData();
    }

    @Override
    public boolean needsUpdate() {
        return cachedConfiguration == null || lastUpdateTime + CesecoreConfiguration.getCacheGlobalConfigurationTime() < System.currentTimeMillis();
    }

    @Override
    public ConfigurationBase getConfiguration() {
        return cachedConfiguration;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public ConfigurationBase getConfiguration(final HashMap data) {
        final ConfigurationBase newConfiguration = getNewConfiguration();
        newConfiguration.loadData(data);
        return newConfiguration;
    }

    @Override
    public ConfigurationBase getNewConfiguration() {
        return new IssueCheckerConfiguration();
    }

    @Override
    public void updateConfiguration(final ConfigurationBase updatedConfiguration) {
        this.cachedConfiguration = updatedConfiguration;
        lastUpdateTime = System.currentTimeMillis();
    }

    @Override
    public Properties getAllProperties() {
        return null;
    }
}
