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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.InvalidParameterException;
import java.util.Map;
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
    private Map<String, Method> databaseValueRegistry;
    private Map<String, Map<String, AccessMatchValue>> nameLookupRegistry;
    private Map<String, AccessMatchValue> defaultValues;
    
    private AccessMatchValueReverseLookupRegistry() {
        databaseValueRegistry = new ConcurrentHashMap<String, Method>();  
        nameLookupRegistry = new ConcurrentHashMap<String, Map<String, AccessMatchValue>>();  
        defaultValues = new ConcurrentHashMap<String, AccessMatchValue>();
    }

    public Set<String> getAllTokenTypes() {
        return databaseValueRegistry.keySet();
    }
    
    /**
     * This method registers a static reverse lookup method for enums implementing the AccessMatchValue
     * interface.  
     * 
     * A method registered to this registry MUST be public, static and have a return type implementing AccessMatchvalue.
     * 
     * @param tokenType A string identifier 
     * @param databaseValueLookupMethod a method that must return an enum extending AccessMatchValue that must be public and static.
     */
    public void registerLookupMethod(String tokenType, Method databaseValueLookupMethod, Map<String, AccessMatchValue> nameLookupMap, AccessMatchValue defaultValue ) {
        if (tokenType == null) {
            throw new InvalidParameterException("Parameter tokenType may not be null");
        } else if (databaseValueLookupMethod == null) {
            throw new InvalidParameterException("Parameter lookupMethod may not be null");
        } else if (databaseValueRegistry.get(tokenType) != null) {
            throw new InvalidMatchValueException("A lookup method linked to the token type " + tokenType + " is already registered.");
        } else if (!Modifier.isPublic(databaseValueLookupMethod.getModifiers())) {
            throw new InvalidMatchValueException("Lookup method was not public, hence invalid. Can not recover.");
        } else if (!Modifier.isStatic(databaseValueLookupMethod.getModifiers())) {
            throw new InvalidMatchValueException("Lookup method was not static, hence invalid. Can not recover.");
        } else if (!AccessMatchValue.class.isAssignableFrom(databaseValueLookupMethod.getReturnType())) {
            throw new InvalidMatchValueException("Lookup method does not return a class that implements the interface "
                    + AccessMatchValue.class.getSimpleName() + " Can not recover.");
        } else {
            databaseValueRegistry.put(tokenType, databaseValueLookupMethod);
        }
        this.nameLookupRegistry.put(tokenType, nameLookupMap);
        this.defaultValues.put(tokenType, defaultValue);
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
            Method callback = databaseValueRegistry.get(tokenType);
            if (callback == null) {
                return null;
            } else {
                try {
                    return (AccessMatchValue) callback.invoke(null, databaseValue);
                } catch (IllegalArgumentException e) {
                    throw new InvalidMatchValueException("IllegalArgumentException thrown", e);
                } catch (IllegalAccessException e) {
                    throw new InvalidMatchValueException("Lookup method was not public", e);
                } catch (InvocationTargetException e) {
                    throw new ReverseMatchValueLookupException(e);
                }
            }
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
        Map<String, AccessMatchValue> valueMap = nameLookupRegistry.get(tokenType);
        if(valueMap == null) {
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
