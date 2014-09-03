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
package org.cesecore.keybind;

import java.util.List;
import java.util.Map;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Signer Object cache.
 * 
 * @version $Id$
 */
public enum InternalKeyBindingCache implements CommonCache<InternalKeyBinding> {
    INSTANCE;

    final private CommonCache<InternalKeyBinding> internalKeyBindingCache = new CommonCacheBase<InternalKeyBinding>() {
        @Override
        protected long getCacheTime() {
            // We never disable storage of InternalKeyBindings in the cache completely
            return Math.max(CesecoreConfiguration.getCacheTimeInternalKeyBinding(), 0);
        }
        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge InternalKeyBindings unless a database select discovers a missing object.
            return 0;
        };
    };

    @Override
    public InternalKeyBinding getEntry(final int signerId) {
        return internalKeyBindingCache.getEntry(signerId);
    }

    @Override
    public boolean shouldCheckForUpdates(final int signerId) {
        return internalKeyBindingCache.shouldCheckForUpdates(signerId);
    }
    
    @Override
    public void updateWith(int signerId, int digest, String name, InternalKeyBinding object) {
        internalKeyBindingCache.updateWith(signerId, digest, name, object);
    }

    @Override
    public void removeEntry(int signerId) {
        internalKeyBindingCache.removeEntry(signerId);
    }
    
    @Override
    public String getName(int id) {
        return internalKeyBindingCache.getName(id);
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        return internalKeyBindingCache.getNameToIdMap();
    }
    
    @Override
    public void flush() {
        internalKeyBindingCache.flush();
    }
    
    @Override
    public void replaceCacheWith(List<Integer> keys) {
        internalKeyBindingCache.replaceCacheWith(keys);
    }
}