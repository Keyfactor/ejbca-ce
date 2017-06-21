/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.List;
import java.util.Map;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Key validator object and name to id lookup cache. Configured through CesecoreConfiguration.getCacheKeyValidatorTime().
 * 
 * @version $Id: KeyValidatorCache.java 25671 2017-04-01 14:29:38Z anjakobs $
 */
public enum KeyValidatorCache implements CommonCache<BaseKeyValidator> {

    INSTANCE;

    private final CommonCache<BaseKeyValidator> cache = new CommonCacheBase<BaseKeyValidator>() {
        @Override
        protected long getCacheTime() {
            return Math.max( CesecoreConfiguration.getCacheKeyValidatorTime(), 0);
        };

        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge BaseKeyValidators unless a database select discovers a missing object.
            return 0L;
        }
    };

    @Override
    public BaseKeyValidator getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return cache.getEntry(id);
    }

    @Override
    public BaseKeyValidator getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }

    @Override
    public void updateWith(int id, int digest, String name, BaseKeyValidator object) {
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
}
