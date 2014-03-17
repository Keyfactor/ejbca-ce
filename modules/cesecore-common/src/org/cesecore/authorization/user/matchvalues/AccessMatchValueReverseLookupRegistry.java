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
import java.util.concurrent.ConcurrentHashMap;

/**
 * This enum-pattern singleton acts as a lookup registry for AccessMatchValue implementations. 
 * Any AccessMatchValue willing to be used has to register itself and its token type here.
 * 
 * @version $Id$
 *
 */
public enum AccessMatchValueReverseLookupRegistry {
    INSTANCE;
    
    // Registry of methods used to look up database values
    private final Map<String, Map<String, AccessMatchValue>> nameLookupRegistry = new ConcurrentHashMap<String, Map<String, AccessMatchValue>>();
    private final Map<String, Map<Integer, AccessMatchValue>> idLookupRegistry = new ConcurrentHashMap<String, Map<Integer, AccessMatchValue>>();
    private final Map<String, AccessMatchValue> defaultValues = new ConcurrentHashMap<String, AccessMatchValue>();

    private AccessMatchValueReverseLookupRegistry() {
        ServiceLoader<? extends AccessMatchValue> serviceLoader = ServiceLoader.load(AccessMatchValue.class);
        for(AccessMatchValue plugin : serviceLoader) {
            AccessMatchValue[] values = plugin.getValues();
            final String tokenType = values[0].getTokenType();
            if (defaultValues.containsKey(tokenType)) {
                throw new InvalidMatchValueException(tokenType + " has already been registered.");
            }
            // If none of the provided AccessMatchValues would volunteer as default we will use the first one as fall-back
            defaultValues.put(tokenType, values[0]);
            final Map<String, AccessMatchValue> nameLookup = new HashMap<String, AccessMatchValue>();
            final Map<Integer, AccessMatchValue> idLookup = new HashMap<Integer, AccessMatchValue>();
            for (final AccessMatchValue value : values) {
                nameLookup.put(value.name(), value);
                idLookup.put(value.getNumericValue(), value);
                if (value.isDefaultValue()) {
                    defaultValues.put(tokenType, value);
                }
            }
            nameLookupRegistry.put(tokenType, nameLookup);
            idLookupRegistry.put(tokenType, idLookup);
        }
    }
    
    public Set<String> getAllTokenTypes() {
        return defaultValues.keySet();
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
    public AccessMatchValue performReverseLookup(String tokenType, int databaseValue) {
        if (tokenType == null) {
            return null;
        } else {
            final Map<Integer, AccessMatchValue> valueMap = idLookupRegistry.get(tokenType);
            if (valueMap == null) {
                return null;
            }
            return valueMap.get(databaseValue);
        }
    }
    
    /**
     * Returns the AccessMatchValue for a given token type and value name
     * 
     * @param tokenType a name representing the sought token type.
     * @param matchValueName the name of the match value
     * @return the sought AccessMatchValue. Returns null if match value not found for the given token type.
     */
    public AccessMatchValue lookupMatchValueFromTokenTypeAndName(String tokenType, String matchValueName) {
        final Map<String, AccessMatchValue> valueMap = nameLookupRegistry.get(tokenType);
        if (valueMap == null) {
            throw new ReverseMatchValueLookupException("Token type of name " + tokenType + " not found.");
        }
        return valueMap.get(matchValueName);
    }

    /**
     * @return the nameLookupMap for a given token type. Never returns null.
     */
    public Map<String, AccessMatchValue> getNameLookupRegistryForTokenType(String tokenType) {
        Map<String, AccessMatchValue> valueMap = nameLookupRegistry.get(tokenType);
        if(valueMap == null) {
            throw new ReverseMatchValueLookupException("Token type of name " + tokenType + " not found.");
        }
        return valueMap;
    }
    
    /**
     * The default value for the given token type. 
     * 
     * @param tokenType the token type asked for 
     * @return the default value for the given token type. May return null if such a value is registered as default.
     */
    public AccessMatchValue getDefaultValueForTokenType(String tokenType) {
        AccessMatchValue result = defaultValues.get(tokenType);
        if(!nameLookupRegistry.containsKey(tokenType)) {
            throw new ReverseMatchValueLookupException("Token type " + tokenType + " does not exist.");
        }
        return result;
    }

}
