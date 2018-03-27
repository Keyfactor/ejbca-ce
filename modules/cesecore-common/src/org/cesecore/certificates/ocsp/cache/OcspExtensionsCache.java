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
package org.cesecore.certificates.ocsp.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;

/**
 * Enum based singleton to contain a Map of OCSP extensions.
 * 
 * Note that this class is currently not thread safe, and use of the reloadCache()-method should be extremely limited. 
 * 
 * @version $Id$
 * 
 */
public enum OcspExtensionsCache {
    INSTANCE;

    private static Logger log; // static initialization happens after the enum instance is constructed, so we can't initialize the logger here

    private Map<String, OCSPExtension> extensionMap;

    private OcspExtensionsCache() {
        initializeLogger();
        reloadCache(buildExtensionsMap());
    }
    
    /** Helper method to assign the log, which can't be done directly from the constructor */
    private static void initializeLogger() {
        log = Logger.getLogger(OcspExtensionsCache.class);
    }

    /**
     * 
     * @return a map containing all loaded extensions. 
     */
    public Map<String, OCSPExtension> getExtensions() {
        return extensionMap;
    }

    /**
     * Method to manually reload the cache. 
     */
    private void reloadCache(Map<String, OCSPExtension> newExtensionMap) {
        extensionMap = newExtensionMap;
    }

    /**
     * Reloads the cache manually, reading configuration anew. 
     */
    public void reloadCache() {
        reloadCache(buildExtensionsMap());
    }
    
    private static Map<String, OCSPExtension> buildExtensionsMap() {
        Map<String, OCSPExtension> result = new HashMap<String, OCSPExtension>();
        ServiceLoader<OCSPExtension> extensionLoader = ServiceLoader.load(OCSPExtension.class);
        for (OCSPExtension extension : extensionLoader) {
            result.put(extension.getOid(), extension);
            if (log.isDebugEnabled()) {
                log.debug("Added OCSP extension with OID: " + extension.getOid() + " to the OCSP extension map");
            }
        }
        return result;
    }
}
