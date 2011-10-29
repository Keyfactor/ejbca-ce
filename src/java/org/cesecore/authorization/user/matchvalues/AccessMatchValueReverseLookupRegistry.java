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

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.CliUserAccessMatchValue;

/**
 * This enum-pattern singleton acts as a lookup registry for AccessMatchValue implementations. 
 * Any AccessMatchValue willing to be used has to register itself and its token type here.
 * 
 * @version $Id$
 *
 */
public enum AccessMatchValueReverseLookupRegistry {
    INSTANCE;
    
    private static final Logger log = Logger.getLogger(AccessMatchValueReverseLookupRegistry.class);
    
    private Map<String, Method> registry;

    static {
        /*
         * FIXME: This is a hack, because we need some sort of annotation or service loader to make sure 
         * that the AccessMatchValue-implementing enums get initialized at runtime. Sadly, enums aren't 
         * initialized until they're called, which causes trouble with this registry. 
         * 
         * The mostly likely solution is to (from here) walk through the entire source tree and initialize 
         * any class implementing the AccessMatchValue interface.
         * 
         * Suggestions on where to move these lines would be appreciated.
         * 
         * -mikek
         */      
        try {
            Class.forName(X500PrincipalAccessMatchValue.class.getName());
            Class.forName(CliUserAccessMatchValue.class.getName());
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            log.error("Failure during match value initialization", e);
        }
    }
    
    private AccessMatchValueReverseLookupRegistry() {
        registry = new ConcurrentHashMap<String, Method>();      
    }

    /**
     * This method registers a static reverse lookup method for enums extending the AccessMatchValue
     * interface.  
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
     * 
     * @param tokenType A string identifier 
     * @param databaseValue
     * @return The AccessMatchValue-extending enum returned by the corresponding lookup method. 
     * @throws InvocationTargetException to wrap any exceptions thrown during the method invocation. 
     */
    public AccessMatchValue performReverseLookup(String tokenType, int databaseValue) {
        if (tokenType == null) {
            return null;
        } else {
            try {
                return (AccessMatchValue) registry.get(tokenType).invoke(null, databaseValue);
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
