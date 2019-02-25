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

package org.ejbca.core.model.validation;

import java.util.List;
import java.util.Map;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Domain blacklist entry and name to id lookup cache. 
 * Configured through CesecoreConfiguration.getCacheDomainBlacklistTime().
 * @version $Id$
 */


public enum DomainBlacklistEntryCache implements CommonCache<DomainBlacklistEntry> {
    INSTANCE;
            
    private final CommonCache<DomainBlacklistEntry> cache = new CommonCacheBase<DomainBlacklistEntry>() {
        @Override
        protected long getCacheTime() {
            return Math.max(CesecoreConfiguration.getCacheDomainBlacklistTime(), 0);
        };

        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge DomainBlacklist unless a database select discovers a missing object.
            return 0L;
        }
    };
    
    @Override
    public DomainBlacklistEntry getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return cache.getEntry(id);
    }

    @Override
    public DomainBlacklistEntry getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }

    /**
     * @param id entry ID
     * @param digest Data.getProtectString(0).hashCode()
     * @param name the fingerprint of the entry object
     * @param object black list entry
     */

    @Override
    public void updateWith(int id, int digest, String name, DomainBlacklistEntry object) {
        cache.updateWith(id, digest, name, object);
    }

    @Override
    public void removeEntry(int id) {
        cache.removeEntry(id);
    }

    @Override
    public String getName(int id) {
        return cache.getName(id);
    }

    @Override
    public Map<String, Integer> getNameToIdMap() {
        return cache.getNameToIdMap();
    }

    @Override
    public void flush() {
        cache.flush();
    }

    @Override
    public void replaceCacheWith(List<Integer> keys) {
        cache.replaceCacheWith(keys);
    }
    @Override
    public boolean willUpdate(int id, int digest) {
        return cache.willUpdate(id, digest);
    }
}