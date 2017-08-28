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
package org.cesecore.roles.member;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Cache of the role member objects.
 * 
 * The cached name is in the form "nameSpace:roleName".
 * 
 * @version $Id$
 */
public enum RoleMemberCache implements CommonCache<RoleMember> {
    INSTANCE;

    private final CommonCacheBase<RoleMember> cache = new CommonCacheBase<RoleMember>() {
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
    public RoleMember getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return cache.getEntry(id);
    }

    @Override
    public RoleMember getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }
    
    @Override
    public void updateWith(final int id, final int digest, final String name, final RoleMember roleMember) {
        //Insert a cloned instance into the cache 
        cache.updateWith(id, digest, String.valueOf(digest), new RoleMember(roleMember));
    }

    @Override
    public void removeEntry(final int id) {
        cache.removeEntry(id);
    }
    
    @Override
    public String getName(int id) {
        throw new UnsupportedOperationException("Role members can't be referenced by name.");
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

    public Set<RoleMember> getAllValues() {
       return cache.getAllEntries();
    }
  
   
}
