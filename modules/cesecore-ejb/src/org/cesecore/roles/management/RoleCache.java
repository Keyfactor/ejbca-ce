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
package org.cesecore.roles.management;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;
import org.cesecore.roles.Role;

/**
 * Cache of the role objects.
 * 
 * The cached name is in the form "nameSpace:roleName".
 * 
 * @version $Id$
 */
public enum RoleCache implements CommonCache<Role> {
    INSTANCE;

    final private CommonCacheBase<Role> cache = new CommonCacheBase<Role>() {
        @Override
        protected long getCacheTime() {
            return CesecoreConfiguration.getCacheAuthorizationTime();
        }
        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge Role unless a database select discovers a missing object.
            return 0;
        };
    };

    @Override
    public Role getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }
    
    @Override
    public void updateWith(final int id, final int digest, final String name, final Role object) {
        cache.updateWith(id, digest, name, object);
    }

    @Override
    public void removeEntry(final int id) {
        cache.removeEntry(id);
    }
    
    @Override
    public String getName(int id) {
        return cache.getName(id);
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
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

    public Set<Role> getAllValues() {
       return cache.getAllEntries();
    }
}
