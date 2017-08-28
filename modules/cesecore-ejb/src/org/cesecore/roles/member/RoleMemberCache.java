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
import org.cesecore.authorization.user.AccessMatchType;
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
    
    /**
     * This map contains a list of RoleMember ids matched to the authentication token they match against. The rationale behind saving just the IDs 
     * is because the list might grow rather large. Any new role members created, edited or removed will invalidate its contents. 
     */
    private final Map<AuthenticationTokenKey, List<Integer>> authenticationTokenToKeyMap = new HashMap<>();

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
        authenticationTokenToKeyMap.clear();
    }

    @Override
    public void removeEntry(final int id) {
        cache.removeEntry(id);
        authenticationTokenToKeyMap.clear();
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
        cache.replaceCacheWith(keys);
        authenticationTokenToKeyMap.clear();
    }

    public Set<RoleMember> getAllValues() {
       return cache.getAllEntries();
    }
    
    /**
     * Delivers a list of cached role members, which have been previously mapped against the provided authentication token. An empty list does *not* 
     * imply that the authentication token lacks matching members, just that such members may not have been cached yet. Should not be used outside
     * of RoleMemberDataSession.
     * 
     * @param authenticationToken an authentication token
     * @return a list of cached role members 
     */
    public List<RoleMember> getCachedRoleMembersForAuthenticationToken(final AuthenticationToken authenticationToken) {
        List<RoleMember> result = null;
        AuthenticationTokenKey key = new AuthenticationTokenKey(authenticationToken);
        if(authenticationTokenToKeyMap.containsKey(key)) {
            result = new ArrayList<>();
            for(int roleMemberIdentifier : authenticationTokenToKeyMap.get(key)) {
                result.add(getEntry(roleMemberIdentifier));
            }
        }
        return result;
    }
    
    /**
     * This method adds an authentication and its known role members to the cache. 
     * 
     * @param authenticationToken an authentication token.
     * @param roleMembers a list of role members.
     */
    public void cacheRoleMembersForAuthenticationToken(final AuthenticationToken authenticationToken, final List<RoleMember> roleMembers) {
        List<Integer> identifiers = new ArrayList<>();
        for (RoleMember roleMember : roleMembers) {
            int roleMemberId = roleMember.getId();
            identifiers.add(roleMemberId);
            if(getEntry(roleMemberId) == null) {
                cache.updateWith(roleMemberId, roleMember.hashCode(), String.valueOf(roleMember.hashCode()), new RoleMember(roleMember));
            }
        }
        authenticationTokenToKeyMap.put(new AuthenticationTokenKey(authenticationToken), identifiers);
    }
    
    /**
     * Private class that provides a search key for recently used authentication tokens. 
     */
    private class AuthenticationTokenKey {
        private final String tokenType;
        private final int preferredMatchKey;
        private final int preferredOperator;
        private final String preferredTokenMatchValue;
        
        public AuthenticationTokenKey(AuthenticationToken authenticationToken) {
            tokenType = authenticationToken.getMetaData().getTokenType();
            preferredMatchKey = authenticationToken.getPreferredMatchKey();
            if(preferredMatchKey != AuthenticationToken.NO_PREFERRED_MATCH_KEY) {
                List<AccessMatchType> accessMatchType= authenticationToken.getMetaData().getAccessMatchValueIdMap().get(preferredMatchKey).getAvailableAccessMatchTypes();
                preferredOperator = accessMatchType.isEmpty() ? AccessMatchType.TYPE_UNUSED.getNumericValue() : accessMatchType.get(0).getNumericValue();
            } else {
                preferredOperator = AccessMatchType.TYPE_UNUSED.getNumericValue();
            }            
            preferredTokenMatchValue = authenticationToken.getPreferredMatchValue();
        }

        private RoleMemberCache getOuterType() {
            return RoleMemberCache.this;
        }
        
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + getOuterType().hashCode();
            result = prime * result + preferredMatchKey;
            result = prime * result + preferredOperator;
            result = prime * result + ((preferredTokenMatchValue == null) ? 0 : preferredTokenMatchValue.hashCode());
            result = prime * result + ((tokenType == null) ? 0 : tokenType.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            AuthenticationTokenKey other = (AuthenticationTokenKey) obj;
            if (!getOuterType().equals(other.getOuterType()))
                return false;
            if (preferredMatchKey != other.preferredMatchKey)
                return false;
            if (preferredOperator != other.preferredOperator)
                return false;
            if (preferredTokenMatchValue == null) {
                if (other.preferredTokenMatchValue != null)
                    return false;
            } else if (!preferredTokenMatchValue.equals(other.preferredTokenMatchValue))
                return false;
            if (tokenType == null) {
                if (other.tokenType != null)
                    return false;
            } else if (!tokenType.equals(other.tokenType))
                return false;
            return true;
        }
    }
}
