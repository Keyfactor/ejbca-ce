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
package org.cesecore.roles.member;

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.user.AccessMatchType;

/**
 * POJO that provides a search key for recently used authentication tokens. 
 * 
 * @version $Id$
 *
 */
public class AuthenticationTokenCacheKey {
    private final String tokenType;
    private final int preferredMatchKey;
    private final int preferredOperator;
    private final String preferredTokenMatchValue;
    
    public AuthenticationTokenCacheKey(AuthenticationToken authenticationToken) {
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

    /**
     * Copy constructor 
     * 
     * @param authenticationTokenCacheKey
     */
    public AuthenticationTokenCacheKey(AuthenticationTokenCacheKey authenticationTokenCacheKey) {
        tokenType = authenticationTokenCacheKey.tokenType;
        preferredMatchKey = authenticationTokenCacheKey.preferredMatchKey;
        preferredOperator = authenticationTokenCacheKey.preferredOperator;
        preferredTokenMatchValue = authenticationTokenCacheKey.preferredTokenMatchValue;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + preferredMatchKey;
        result = prime * result + preferredOperator;
        result = prime * result + ((preferredTokenMatchValue == null) ? 0 : preferredTokenMatchValue.hashCode());
        result = prime * result + ((tokenType == null) ? 0 : tokenType.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AuthenticationTokenCacheKey other = (AuthenticationTokenCacheKey) obj;
 
        if (preferredMatchKey != other.preferredMatchKey) {
            return false;
        }
        if (preferredOperator != other.preferredOperator) {
            return false;
        }
        if (preferredTokenMatchValue == null) {
            if (other.preferredTokenMatchValue != null) {
                return false;
            }
        } else if (!preferredTokenMatchValue.equals(other.preferredTokenMatchValue)) {
            return false;
        }
        if (tokenType == null) {
            if (other.tokenType != null) {
                return false;
            }
        } else if (!tokenType.equals(other.tokenType)) {
            return false;
        }
        return true;
    }
}
