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
package org.ejbca.core.ejb.ca.publisher;

import java.util.List;
import java.util.Map;

import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.ca.publisher.BasePublisher;

/**
 * Publisher object and name to id lookup cache. Configured through CesecoreConfiguration.getCachePublisherTime().
 * 
 * @version $Id$
 */
public enum PublisherCache implements CommonCache<BasePublisher> {
    INSTANCE;

    final private CommonCache<BasePublisher> cache = new CommonCacheBase<BasePublisher>() {
        @Override
        protected long getCacheTime() {
            return EjbcaConfiguration.getCachePublisherTime();
        };
        @Override
        protected long getMaxCacheLifeTime() {
            // Publishers are not short-lived objects with long cache times so we disable it
            return 0L;
        };
    };

    @Override
    public BasePublisher getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }
    
    @Override
    public void updateWith(int id, int digest, String name, BasePublisher object) {
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
}
