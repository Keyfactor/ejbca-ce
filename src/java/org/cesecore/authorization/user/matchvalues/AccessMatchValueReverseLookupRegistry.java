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
    
    private Map<String, Method> registry;
    
    private AccessMatchValueReverseLookupRegistry() {
        registry = new ConcurrentHashMap<String, Method>();      
    }

    /**
     * This method registers a static reverse lookup method for enums implementing the AccessMatchValue
     * interface.  
     * 
     * A method registered to this registry MUST be public, static and have a return type implementing AccessMatchvalue.
     * 
     * @param tokenType A string identifier 
     * @param lookupMethod a method that must return an enum extending AccessMatchValue that must be public and static.
     */
    public void registerLookupMethod(String tokenType, Method lookupMethod) {
        if (tokenType == null) {
            throw new InvalidParameterException("Parameter tokenType may not be null");
        } else if (lookupMethod == null) {
            throw new InvalidParameterException("Parameter lookupMethod may not be null");
        } else if (registry.get(tokenType) != null) {
            throw new InvalidMatchValueException("A lookup method linked to the token type " + tokenType + " is already registered.");
        } else if (!Modifier.isPublic(lookupMethod.getModifiers())) {
            throw new InvalidMatchValueException("Lookup method was not public, hence invalid. Can not recover.");
        } else if (!Modifier.isStatic(lookupMethod.getModifiers())) {
            throw new InvalidMatchValueException("Lookup method was not static, hence invalid. Can not recover.");
        } else if (!AccessMatchValue.class.isAssignableFrom(lookupMethod.getReturnType())) {
            throw new InvalidMatchValueException("Lookup method does not return a class that implements the interface "
                    + AccessMatchValue.class.getSimpleName() + " Can not recover.");
        } else {
            registry.put(tokenType, lookupMethod);
        }
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
            Method callback = registry.get(tokenType);
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

}
