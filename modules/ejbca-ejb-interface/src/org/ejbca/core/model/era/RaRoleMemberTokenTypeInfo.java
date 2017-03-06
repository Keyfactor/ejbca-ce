/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.Map;

/**
 * Contains information from {@link org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry}
 * @version $Id$
 */
public final class RaRoleMemberTokenTypeInfo implements Serializable {

    private static final long serialVersionUID = 1L;


    private final Map<String,Integer> matchKeys;
    private final String defaultMatchKey;
    private final boolean issuedByCA;
    private final boolean hasMatchValue;
    private final int matchOperator;
    
    public RaRoleMemberTokenTypeInfo(final Map<String,Integer> matchKeys, final String defaultMatchKey, final boolean issuedByCA, final boolean hasMatchValue,
            final int matchOperator) {
        this.matchKeys = matchKeys;
        this.defaultMatchKey = defaultMatchKey;
        this.issuedByCA = issuedByCA;
        this.hasMatchValue = hasMatchValue;
        this.matchOperator = matchOperator;
    }

    public Map<String,Integer> getMatchKeysMap() {
        return matchKeys;
    }

    public String getDefaultMatchKey() {
        return defaultMatchKey;
    }
    
    public boolean isIssuedByCA() {
        return issuedByCA;
    }
    
    public boolean getHasMatchValue() {
        return hasMatchValue;
    }
    
    public int getMatchOperator() {
        return matchOperator;
    }
    
    public void merge(final RaRoleMemberTokenTypeInfo other) {
        matchKeys.putAll(other.matchKeys);
        // the default match key shouldn't differ
    }
}
