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
package org.cesecore.authentication.tokens;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Common functions for meta data definitions for AuthentcationTokens that should be auto-detected via ServiceLoader of AuthenticationTokenMetaData.
 * 
 * @version $Id$
 */
public abstract class AuthenticationTokenMetaDataBase implements AuthenticationTokenMetaData {
    
    private final String tokenType;
    private final List<? extends AccessMatchValue> accessMatchValues;
    private final boolean userConfigurable;
    private final Map<Integer,AccessMatchValue> accessMatchValueIdMap = new HashMap<>();
    private final Map<String,AccessMatchValue> accessMatchValueNameMap = new HashMap<>();
    private final AccessMatchValue defaultAccessMatchValue;

    protected AuthenticationTokenMetaDataBase(final String tokenType, final List<? extends AccessMatchValue> accessMatchValues, final boolean userConfigurable) {
        this.tokenType = tokenType;
        this.accessMatchValues = accessMatchValues;
        this.userConfigurable = userConfigurable;
        AccessMatchValue defaultAccessMatchValue = null;
        for (final AccessMatchValue accessMatchValue : getAccessMatchValues()) {
            accessMatchValueIdMap.put(accessMatchValue.getNumericValue(), accessMatchValue);
            accessMatchValueNameMap.put(accessMatchValue.name(), accessMatchValue);
            if (defaultAccessMatchValue == null || accessMatchValue.isDefaultValue()) {
                defaultAccessMatchValue = accessMatchValue;
            }
        }
        this.defaultAccessMatchValue = defaultAccessMatchValue;
    }

    @Override
    public String getTokenType() {
        return tokenType;
    }

    @Override
    public boolean isUserConfigurable() {
        return userConfigurable;
    }

    @Override
    public List<? extends AccessMatchValue> getAccessMatchValues() {
        return accessMatchValues;
    }

    @Override
    public Map<Integer,AccessMatchValue> getAccessMatchValueIdMap() {
        return accessMatchValueIdMap;
    }

    @Override
    public Map<String,AccessMatchValue> getAccessMatchValueNameMap() {
        return accessMatchValueNameMap;
    }

    @Override
    public AccessMatchValue getAccessMatchValueDefault() {
        return defaultAccessMatchValue;
    }
}
