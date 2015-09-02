/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.config;

import java.util.HashMap;
import java.util.Properties;

import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.ConfigurationCache;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Class Holding cache variable for available custom certificate extensions configuration.
 * 
 * Needed because EJB spec does not allow volatile, non-final fields in session beans.
 * 
 * @version $Id$
 */
public class AvailableCustomCertificateExtensionsConfigurationCache implements ConfigurationCache {

    /**
     * Cache variable containing the available custom certificate extensions configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private volatile ConfigurationBase cache = null;
    /** help variable used to control that updates are not performed to often. */
    private volatile long lastUpdateTime = -1;  

    @Override
    public boolean needsUpdate() {
        return cache==null || lastUpdateTime + EjbcaConfiguration.getCacheGlobalConfigurationTime() < System.currentTimeMillis();
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
        cache = configuration;
        lastUpdateTime = System.currentTimeMillis();
    }
    
    @Override
    public ConfigurationBase getNewConfiguration() {
       return new AvailableCustomCertificateExtensionsConfiguration();      
    }

    @Override
    public Properties getAllProperties() {
        return null;
    }
}
