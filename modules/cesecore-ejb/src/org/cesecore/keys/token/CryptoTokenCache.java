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
package org.cesecore.keys.token;

import java.util.List;
import java.util.Map;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * CryptoToken Object cache.
 * 
 * @version $Id$
 */
public enum CryptoTokenCache implements CommonCache<CryptoToken> {
    INSTANCE;

    final private CommonCache<CryptoToken> cryptoTokenCache = new CommonCacheBase<CryptoToken>() {
        @Override
        protected long getCacheTime() {
            // We should never disable storage of CryptoTokens in the cache completely, since we want to keep any activation
            // So never use cache value "-1" in the setting, use the value 0 instead.
            return CesecoreConfiguration.getCacheTimeCryptoToken();
        }
        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge CryptoTokens unless a database select discovers a missing object.
            return 0;
        };
    };

    @Override
    public CryptoToken getEntry(final int cryptoTokenId) {
        return cryptoTokenCache.getEntry(cryptoTokenId);
    }

    @Override
    public boolean shouldCheckForUpdates(final int cryptoTokenId) {
        return cryptoTokenCache.shouldCheckForUpdates(cryptoTokenId);
    }
    
    @Override
    public void updateWith(int cryptoTokenId, int digest, String name, CryptoToken object) {
        cryptoTokenCache.updateWith(cryptoTokenId, digest, name, object);
    }

    @Override
    public void removeEntry(int cryptoTokenId) {
        cryptoTokenCache.removeEntry(cryptoTokenId);
    }
    
    @Override
    public String getName(int id) {
        return cryptoTokenCache.getName(id);
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        return cryptoTokenCache.getNameToIdMap();
    }
    
    @Override
    public void flush() {
        cryptoTokenCache.flush();
    }
    
    @Override
    public void flushWith(List<Integer> keys) {
        cryptoTokenCache.flushWith(keys);
    }
}
