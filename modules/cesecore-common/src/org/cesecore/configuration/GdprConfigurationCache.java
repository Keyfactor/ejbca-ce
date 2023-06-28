/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.configuration;

import java.util.Map;

import org.apache.log4j.Logger;

public enum GdprConfigurationCache {
    INSTANCE;
    
    // redact all if end entity profile is deleted or in RA??
    // possibly populate from a cesecore-.properties file or system configuration in future
    // what happens with EMPTY profle
    private static final GdprConfiguration GDPR_CONFIG_GLOBAL = new GdprConfiguration(true);

    private final Logger LOG = Logger.getLogger(GdprConfigurationCache.class);
    
    /** Cache of mappings between profileId and configuration, most cases in EJBs */
    private volatile Map<Integer, GdprConfiguration> idToConfigCache = null;
    /** Cache of mappings between profileName and configuration, requests in REST, SOAP, CLI etc */
    private volatile Map<String, GdprConfiguration> nameToConfigCache = null;
    
    // only to be used from EndEntityProfileCache
    // Locking is handled at EndEntityProfileCache and whole map is updated in one go
    public void updateGdprCache(Map<Integer, GdprConfiguration> idToConfigCache, 
            Map<String, GdprConfiguration> nameToConfigCache) {
        this.idToConfigCache = idToConfigCache;
        this.nameToConfigCache = nameToConfigCache;
        LOG.debug("Updated GdprConfigurationCache.");
    }
    
    public GdprConfiguration getGdprConfiguration(int endEntityProfileId) {
        GdprConfiguration config = this.idToConfigCache.get(endEntityProfileId);
        return config != null ? config :  GDPR_CONFIG_GLOBAL;
    }
    
    public GdprConfiguration getGdprConfiguration(String endEntityProfileName) {
        GdprConfiguration config = this.nameToConfigCache.get(endEntityProfileName);
        return config != null ? config :  GDPR_CONFIG_GLOBAL;
    }    

}
