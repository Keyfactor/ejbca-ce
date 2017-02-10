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
package org.cesecore.authorization.user.matchvalues;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;

/**
 * This enum-pattern singleton acts as a lookup registry for AccessMatchValue implementations. 
 * Any AccessMatchValue willing to be used has to register itself and its token type here.
 * 
 * @version $Id$
 *
 */
public enum AccessMatchValueReverseLookupRegistry {
    INSTANCE;
    
    private final Logger log = Logger.getLogger(AccessMatchValueReverseLookupRegistry.class);
    
    // Registry of methods used to look up database values
    private final Map<String, AuthenticationTokenMetaData> metaDatas = new HashMap<>();

    private AccessMatchValueReverseLookupRegistry() {
        for (final AuthenticationTokenMetaData metaData : ServiceLoader.load(AuthenticationTokenMetaData.class)) {
            register(metaData);
        }
    }

    /** package accessible register class also for use from JUnit test */
    void register(final AuthenticationTokenMetaData metaData) {
        if (metaData!=null && metaData.getTokenType()!=null && metaData.getAccessMatchValues()!=null && !metaData.getAccessMatchValues().isEmpty()) {
            metaDatas.put(metaData.getTokenType(), metaData);
            if (log.isDebugEnabled()) {
                log.debug("Registered AuthenticationToken of type " + metaData.getTokenType() +" with match keys " + metaData.getAccessMatchValues().toString());
            }
        }
    }

    public Set<String> getAllTokenTypes() {
        return metaDatas.keySet();
    }
    
    /**
     * This method performs a reverse lookup given a token type and an integer, by using already registered callback method
     * to translate those values into an AccessMatchValue. If no corresponding callback method has been registered, this method
     * will return null.
     * 
     * @param tokenType A string identifier 
     * @param databaseValue the numeric value from the database.
     * @return The AccessMatchValue-extending enum returned by the corresponding lookup method, null if token type isn't registered. 
     */
    public AccessMatchValue performReverseLookup(final String tokenType, final int databaseValue) {
        final AuthenticationTokenMetaData metaData = metaDatas.get(tokenType);
        return metaData == null ? null : metaData.getAccessMatchValueIdMap().get(databaseValue);
    }
    
    /**
     * Returns the AccessMatchValue for a given token type and value name
     * 
     * @param tokenType a name representing the sought token type.
     * @param matchValueName the name of the match value
     * @return the sought AccessMatchValue. Returns null if match value not found for the given token type.
     */
    public AccessMatchValue lookupMatchValueFromTokenTypeAndName(final String tokenType, final String matchValueName) {
        final AuthenticationTokenMetaData metaData = metaDatas.get(tokenType);
        return metaData == null ? null : metaData.getAccessMatchValueNameMap().get(matchValueName);
    }

    /**
     * @return the nameLookupMap for a given token type. Never returns null.
     */
    public Map<String, AccessMatchValue> getNameLookupRegistryForTokenType(final String tokenType) {
        final AuthenticationTokenMetaData metaData = metaDatas.get(tokenType);
        if (metaData == null) {
            throw new ReverseMatchValueLookupException("Token type of name " + tokenType + " not found.");
        }
        return metaData.getAccessMatchValueNameMap();
    }
    
    /**
     * The default value for the given token type. 
     * 
     * @param tokenType the token type asked for 
     * @return the default value for the given token type. May return null if such a value is registered as default.
     */
    public AccessMatchValue getDefaultValueForTokenType(final String tokenType) {
        final AuthenticationTokenMetaData metaData = metaDatas.get(tokenType);
        if (metaData == null) {
            throw new ReverseMatchValueLookupException("Token type of name " + tokenType + " not found.");
        }
        return metaData.getAccessMatchValueDefault();
    }
}
