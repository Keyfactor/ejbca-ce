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
package org.ejbca.core.ejb.signer;

import java.util.Map;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * Signer Object cache.
 * 
 * @version $Id$
 */
public enum SignerMappingCache implements CommonCache<SignerMapping> {
    INSTANCE;

    final private CommonCache<SignerMapping> signerMappingCache = new CommonCacheBase<SignerMapping>() {
        @Override
        protected long getCacheTime() {
            // We never disable storage of Signers in the cache completely
            return Math.max(CesecoreConfiguration.getCacheTimeSignerMapping(), 0);
        }
        @Override
        protected long getMaxCacheLifeTime() {
            // We never purge Signer unless a database select discovers a missing object.
            return 0;
        };
    };

    @Override
    public SignerMapping getEntry(final int signerId) {
        return signerMappingCache.getEntry(signerId);
    }

    @Override
    public boolean shouldCheckForUpdates(final int signerId) {
        return signerMappingCache.shouldCheckForUpdates(signerId);
    }
    
    @Override
    public void updateWith(int signerId, int digest, String name, SignerMapping object) {
        signerMappingCache.updateWith(signerId, digest, name, object);
    }

    @Override
    public void removeEntry(int signerId) {
        signerMappingCache.removeEntry(signerId);
    }
    
    @Override
    public String getName(int id) {
        return signerMappingCache.getName(id);
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        return signerMappingCache.getNameToIdMap();
    }
    
    @Override
    public void flush() {
        signerMappingCache.flush();
    }
}