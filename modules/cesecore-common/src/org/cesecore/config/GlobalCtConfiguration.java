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
package org.cesecore.config;

import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.configuration.ConfigurationBase;

/**
 * Contains global Certificate Transparency-related settings
 */

public class GlobalCtConfiguration extends ConfigurationBase {

    private static final long serialVersionUID = 1L;

    public static final String CT_CONFIGURATION_ID = "GLOBAL_CT_CONFIG";

    private static final String CT_CACHE_ENABLED_KEY = "ct_cache_enabled";
    private static final String CT_CACHE_SIZE_KEY = "ct_cache_size";
    private static final String CT_CACHE_CLEANUP_INTERVAL_KEY = "ct_cache_cleanup_interval";
    private static final String CT_CACHE_FAST_FAIL_ENABLED_KEY = "ct_cache_fast_fail_enabled";
    private static final String CT_CACHE_FAST_FAIL_BACKOFF_KEY = "ct_cache_fast_fail_backoff";
    private static final String GOOGLE_CT_POLICY = "google_ct_policy";
    
    private static final long DEFAULT_CACHE_SIZE = 1000000L;
    private static final long DEFAULT_CLEANUP_INTERVAL = 10000L;
    private static final boolean DEFAULT_CACHE_ENABLED = true;
    private static final boolean DEFAULT_FAST_FAIL_ENABLED = true;
    private static final long DEFAULT_FAST_FAIL_BACKOFF = 1000L;

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, LATEST_VERSION);
        }

    }

    @Override
    public String getConfigurationId() {
        return CT_CONFIGURATION_ID;
    }

    public boolean getCtCacheEnabled() {
        return getBoolean(CT_CACHE_ENABLED_KEY, DEFAULT_CACHE_ENABLED);
    }

    public void setCtCacheEnabled(final boolean value) {
        data.put(CT_CACHE_ENABLED_KEY, value);
    }

    public long getCtCacheSize() {
        Long value = (Long) data.get(CT_CACHE_SIZE_KEY);
        if (value == null) {
            setCtCacheSize(DEFAULT_CACHE_SIZE);
        }
        return (Long) data.get(CT_CACHE_SIZE_KEY);
    }

    public void setCtCacheSize(final long ctCacheSize) {
        data.put(CT_CACHE_SIZE_KEY, ctCacheSize);
    }

    public long getCtCacheCleanupInterval() {
        Long value = (Long) data.get(CT_CACHE_CLEANUP_INTERVAL_KEY);
        if (value == null) {
            setCtCacheCleanupInterval(DEFAULT_CLEANUP_INTERVAL);
        }
        return (Long) data.get(CT_CACHE_CLEANUP_INTERVAL_KEY);
    }

    public void setCtCacheCleanupInterval(final long interval) {
        data.put(CT_CACHE_CLEANUP_INTERVAL_KEY, interval);
    }

    public boolean getCtCacheFastFailEnabled() {
        return getBoolean(CT_CACHE_FAST_FAIL_ENABLED_KEY, DEFAULT_FAST_FAIL_ENABLED);
    }

    public void setCtCacheFastFailEnabled(final boolean fastFailEnabled) {
        data.put(CT_CACHE_FAST_FAIL_ENABLED_KEY, fastFailEnabled);
    }

    public long getCtCacheFastFailBackoff() {
        Long value = (Long) data.get(CT_CACHE_FAST_FAIL_BACKOFF_KEY);
        if (value == null) {
            setCtCacheFastFailBackoff(DEFAULT_FAST_FAIL_BACKOFF);
        }
        return (Long) data.get(CT_CACHE_FAST_FAIL_BACKOFF_KEY);
    }

    public void setCtCacheFastFailBackoff(final long backoff) {
        data.put(CT_CACHE_FAST_FAIL_BACKOFF_KEY, backoff);
    }
    
    public GoogleCtPolicy getGoogleCtPolicy() {
        final GoogleCtPolicy googleCtPolicy = (GoogleCtPolicy) data.get(GOOGLE_CT_POLICY);
        if (googleCtPolicy == null) {
            return new GoogleCtPolicy();
        }
        return googleCtPolicy;
    }

    public void setGoogleCtPolicy(final GoogleCtPolicy value) {
        data.put(GOOGLE_CT_POLICY, value);
    }

}
