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
package org.cesecore.certificates.ca.internal;

import java.util.List;
import java.util.Map;

import org.cesecore.certificates.ca.CACommon;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * CA object and name to id lookup cache. Configured through CesecoreConfiguration.getCacheCaTimeInCaSession().
 * 
 * @version $Id$
 */
public enum CaCache implements CommonCache<CACommon> {
    INSTANCE;

    final private CommonCache<CACommon> caCache = new CommonCacheBase<CACommon>() {
        @Override
        protected long getCacheTime() {
            return CesecoreConfiguration.getCacheCaTimeInCaSession();
        };
        @Override
        protected long getMaxCacheLifeTime() {
            // CAs are not short-lived objects with long cache times so we disable it
            return 0L;
        };
    };

    @Override
    public CACommon getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return caCache.getEntry(id);
    }

    @Override
    public CACommon getEntry(final int caId) {
        return caCache.getEntry(caId);
    }

    @Override
    public boolean shouldCheckForUpdates(final int caId) {
        return caCache.shouldCheckForUpdates(caId);
    }
    
    @Override
    public void updateWith(int caId, int digest, String name, CACommon caInterface) {
        caCache.updateWith(caId, digest, name, caInterface);
    }

    @Override
    public void removeEntry(int caId) {
        caCache.removeEntry(caId);
    }
    
    @Override
    public String getName(int id) {
        return caCache.getName(id);
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        return caCache.getNameToIdMap();
    }
    
    @Override
    public void flush() {
        caCache.flush();
    }
    
    @Override
    public void replaceCacheWith(List<Integer> keys) {
        caCache.replaceCacheWith(keys);
    }
    
    @Override
    public boolean willUpdate(int id, int digest) {
        return caCache.willUpdate(id, digest);
    }

}
