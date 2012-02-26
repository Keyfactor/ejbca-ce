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
package org.cesecore.util;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.cesecore.jndi.JndiHelper;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public enum EjbRemoteHelper {
    INSTANCE;

    private Map<Class<?>, Object> interfaceCache; 
    
    /**
     * Returns a cached remote session bean.
     * 
     * @param key the @Remote-appended interface for this session bean
     * @return the sought interface, or null if it doesn't exist in JNDI context.
     */
    public <T> T getRemoteSession(final Class<T> key) {
        if(interfaceCache == null) {
            interfaceCache = new ConcurrentHashMap<Class<?>, Object>();
        }
        @SuppressWarnings("unchecked")
        T session = (T) interfaceCache.get(key);
        if (session == null) {
            session = JndiHelper.getRemoteSession(key);
            if (session != null) {
                interfaceCache.put(key, session);
            }
        }
        return session;
    }
}
