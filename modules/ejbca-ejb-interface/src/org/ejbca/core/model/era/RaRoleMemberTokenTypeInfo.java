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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Contains information from {@link org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry}
 * @version $Id$
 */
public final class RaRoleMemberTokenTypeInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    /*public final static class MatchKeyInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int number;
        private final String name;
        public MatchKeyInfo(int number, String name) {
            this.number = number;
            this.name = name;
        }
        public int getNumber() { return number; }
        public String getName() { return name; }
    }*/
    
    //private final Set<MatchKeyInfo> matchKeys;
    private final Map<String,Integer> matchKeys;
    private final String defaultMatchKey;
    
    //public RaRoleMemberTokenTypeInfo(final Set<MatchKeyInfo> matchKeys, final String defaultMatchKey) {
    public RaRoleMemberTokenTypeInfo(final Map<String,Integer> matchKeys, final String defaultMatchKey) {
        this.matchKeys = matchKeys;
        this.defaultMatchKey = defaultMatchKey;
    }

    public Map<String,Integer> getMatchKeysMap() {
        return matchKeys;
    }

    public String getDefaultMatchKey() {
        return defaultMatchKey;
    }
    
    public void merge(final RaRoleMemberTokenTypeInfo other) {
        matchKeys.putAll(other.matchKeys);
        // the default match key shouldn't differ
    }
}
