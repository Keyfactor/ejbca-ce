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

    /** NOTE: diff between EJBCA and CESeCore */
    public final static String MODULE_EJBCA = "ejbca-ejb";
    public final static String MODULE_TEST = "systemtests-ejb";
    
    private Map<Class<?>, Object> interfaceCache; 
    
    /**
     * Returns a cached remote session bean.
     * 
     * @param key the @Remote-appended interface for this session bean
     * @return the sought interface, or null if it doesn't exist in JNDI context.
     */
    public <T> T getRemoteSession(final Class<T> key) {
        return getRemoteSession(key, null);
    }

    /**
     * Returns a cached remote session bean.
     * 
     * @param key the @Remote-appended interface for this session bean
     * @param module the module where the bean is deployed, i.e. systemtests-ejb, if null defaults to ejbca-ejb.
     * @return the sought interface, or null if it doesn't exist in JNDI context.
     */
    public <T> T getRemoteSession(final Class<T> key, String module) {
        if(interfaceCache == null) {
            interfaceCache = new ConcurrentHashMap<Class<?>, Object>();
        }
        @SuppressWarnings("unchecked")
        T session = (T) interfaceCache.get(key);
        if (session == null) {
            if (module == null) {
                // NOTE: diff between EJBCA and CESeCore
                module = EjbRemoteHelper.MODULE_EJBCA;
            }
            session = JndiHelper.getRemoteSession(key, module);
            if (session != null) {
                interfaceCache.put(key, session);
            }
        }
        return session;
    }

}
