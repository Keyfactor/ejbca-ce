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
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.config.OcspConfiguration;

/**
 * Enum based singleton to contain a Map of OCSP extensions.
 * 
 * @version $Id$
 * 
 */
public enum OcspExtensionsCache {
    INSTANCE;

    private static final Logger log = Logger.getLogger(OcspExtensionsCache.class);

    private final Map<String, OCSPExtension> extensionMap;

    private OcspExtensionsCache() {
        extensionMap = new HashMap<String, OCSPExtension>();
        initCache();
    }

    
    public Map<String, OCSPExtension> getExtensions() {
        return extensionMap;
    }
    
    private void initCache() {
        Iterator<String> extensionClasses = OcspConfiguration.getExtensionClasses().iterator();
        Iterator<String> extensionOids = OcspConfiguration.getExtensionOids().iterator();

        while (extensionClasses.hasNext()) {
            String clazz = extensionClasses.next();
            String oid =  extensionOids.next();
            OCSPExtension ext = null;
            try {
                ext = (OCSPExtension) Class.forName(clazz).newInstance();
            } catch (Exception e) {
                log.error("Can not create extension with class " + clazz, e);
                continue;
            }
            extensionMap.put(oid, ext);
        }
    }

}
