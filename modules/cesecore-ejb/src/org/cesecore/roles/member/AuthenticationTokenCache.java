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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.CommonCache;
import org.cesecore.internal.CommonCacheBase;

/**
 * This cache saves authentication token checks. 
 * 
 * @version $Id$
 */
public enum AuthenticationTokenCache implements CommonCache<AuthenticationTokenCacheKey> {
    INSTANCE;

    private final CommonCacheBase<AuthenticationTokenCacheKey> cache = new CommonCacheBase<AuthenticationTokenCacheKey>() {
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
    
    /**
     * This map contains a list of RoleMember ids matched to the authentication token they match against. The rationale behind saving just the IDs 
     * is because the list might grow rather large. Any new role members created, edited or removed will invalidate its contents. 
     */
    private final Map<AuthenticationTokenCacheKey, List<Integer>> authenticationTokenToKeyMap = new HashMap<>();

    @Override
    public AuthenticationTokenCacheKey getEntry(final Integer id) {
        if (id == null) {
            return null;
        }
        return cache.getEntry(id);
    }

    @Override
    public AuthenticationTokenCacheKey getEntry(final int id) {
        return cache.getEntry(id);
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        return cache.shouldCheckForUpdates(id);
    }
    
    @Override
    public void updateWith(final int id, final int digest, final String name, final AuthenticationTokenCacheKey authenticationTokenCacheKey) {
        //Insert a cloned instance into the cache 
        cache.updateWith(id, digest, String.valueOf(digest), new AuthenticationTokenCacheKey(authenticationTokenCacheKey));
        authenticationTokenToKeyMap.clear();
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
        authenticationTokenToKeyMap.clear();
    }
    

    @Override
    public void replaceCacheWith(List<Integer> keys) {
        throw new UnsupportedOperationException("Operation not applicable for this subtype of cache");
    }

    public Set<AuthenticationTokenCacheKey> getAllValues() {
       return cache.getAllEntries();
    }
    
    /**
     * Delivers a list of cached role members, which have been previously mapped against the provided authentication token. An empty list does *not* 
     * imply that the authentication token lacks matching members, just that such members may not have been cached yet. Should not be used outside
     * of RoleMemberDataSession.
     * 
     * @param authenticationToken an authentication token
     * @return a list IDs of cached role members, or null if not found/entry has expired.
     */
    public List<Integer> getCachedRoleMembersForAuthenticationToken(final AuthenticationToken authenticationToken) {
        AuthenticationTokenCacheKey key = new AuthenticationTokenCacheKey(authenticationToken);
        //If there exists an entry
        if (authenticationTokenToKeyMap.containsKey(key)) {
            //And that entry is still valid
            if (!shouldCheckForUpdates(key.hashCode())) {
                return authenticationTokenToKeyMap.get(key);
            } else {
                removeEntry(key.hashCode());
                authenticationTokenToKeyMap.remove(key);
                return null;
            }
        } else {
            return null;
        }
    }
    
    /**
     * This method adds an authentication token and its known role members to the cache. 
     * 
     * @param authenticationToken an authentication token.
     * @param roleMembers a list of role members that the authentication token has identified for. 
     */
    public void cacheRoleMembersForAuthenticationToken(final AuthenticationToken authenticationToken, final List<RoleMember> roleMembers) {
        List<Integer> identifiers = new ArrayList<>();
        AuthenticationTokenCacheKey authenticationTokenCacheKey = new AuthenticationTokenCacheKey(authenticationToken);
        cache.updateWith(authenticationTokenCacheKey.hashCode(), authenticationTokenCacheKey.hashCode(),
                String.valueOf(authenticationTokenCacheKey.hashCode()), authenticationTokenCacheKey);
        for (RoleMember roleMember : roleMembers) {
            int roleMemberId = roleMember.getId();
            identifiers.add(roleMemberId);
        }
        authenticationTokenToKeyMap.put(new AuthenticationTokenCacheKey(authenticationToken), identifiers);
    }
    
    
}
