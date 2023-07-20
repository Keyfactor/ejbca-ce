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
    
    // initialized with falsy values
    private static GdprConfiguration REDACT_DEFAULT = new GdprConfiguration(false);
    private static GdprConfiguration REDACT_ENFORCED = null;

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
    
    // keeping these as boolean to keep it simple and updating them needs limited change
    public void updateGdprNodeLocalSettings(boolean redactByDefaultUpdate, boolean redactEnforcedUpdate) {
        REDACT_DEFAULT = new GdprConfiguration(redactByDefaultUpdate || redactEnforcedUpdate);
        if(redactEnforcedUpdate) {
            REDACT_ENFORCED = new GdprConfiguration(true);
        } else {
            REDACT_ENFORCED = null;
        }
    }
    
    public GdprConfiguration getGdprConfiguration() {
        return REDACT_DEFAULT;
    }
    
    public GdprConfiguration getGdprConfiguration(int endEntityProfileId) {
        if (REDACT_ENFORCED!=null) {
            return REDACT_ENFORCED;
        }
        GdprConfiguration config = this.idToConfigCache.get(endEntityProfileId);
        return config != null ? config :  REDACT_DEFAULT;
    }
    
    public GdprConfiguration getGdprConfiguration(String endEntityProfileName) {
        if (REDACT_ENFORCED!=null) {
            return REDACT_ENFORCED;
        }
        GdprConfiguration config = this.nameToConfigCache.get(endEntityProfileName);
        return config != null ? config :  REDACT_DEFAULT;
    }    

}
