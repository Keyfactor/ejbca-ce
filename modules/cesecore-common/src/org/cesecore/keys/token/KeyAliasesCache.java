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
package org.cesecore.keys.token;

import java.security.PublicKey;

import org.cesecore.internal.CommonCacheBase;

/**
 * Cache for Key aliases (used in Azure and AWS Crypto Token, but is generic). Caches a public key, with alias as key
 */
public class KeyAliasesCache extends CommonCacheBase<PublicKey> {

    /** cache time of the overall cache, seeing if we need to re-read aliases */
    long lastUpdate = 0;

    public KeyAliasesCache() {}

    public KeyAliasesCache(KeyAliasesCache clone) {
        this.cache.putAll(clone.cache);
        this.nameToIdMap.putAll(clone.nameToIdMap);
    }
    
    @Override
    public PublicKey getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return super.getEntry(id);
    }

    @Override
    protected long getCacheTime() {
        return 60000; // Cache key aliases for 60 seconds
    }

    @Override
    protected long getMaxCacheLifeTime() {
        return 60000; // Cache key aliases for 60 seconds
    }

    public void updateCacheTimeStamp() {
        lastUpdate = System.currentTimeMillis();
    }
    @Override
    public void flush() {
        lastUpdate = 0;
        super.flush();
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        if (id == 0) {
            // The whole cache itself needs refresh?
            final long now = System.currentTimeMillis();
            return (lastUpdate+getCacheTime()<now); // true if "now" has passed end of cache time
        }
        return super.shouldCheckForUpdates(id);
    }
}
