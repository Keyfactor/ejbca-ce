/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.File;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;

/**
 * Helper class to get, and initialize, the highest priority PKCS11SlotListWrapper.
 */
public class PKCS11SlotListWrapperHelper {
    
    private static final Logger log = Logger.getLogger(PKCS11SlotListWrapperHelper.class);

    public static PKCS11SlotListWrapper getSlotListWrapper(final File pkcs11Library) {
        // We create the META-INF/services file during build in EJBCA with:
        //<buildservicemanifest interface="org.cesecore.keys.token.PKCS11SlotListWrapperFactory" file="${cesecore-common.dir}/build/classes" classpath="manifest.classpath"/>
        PKCS11SlotListWrapperFactory factory = null;
        final ServiceLoader<? extends PKCS11SlotListWrapperFactory> serviceLoader = ServiceLoader.load(PKCS11SlotListWrapperFactory.class);
        for (PKCS11SlotListWrapperFactory slotListWrapperFactory : serviceLoader) {
            if (factory == null || slotListWrapperFactory.getPriority() > factory.getPriority()) {
                factory = slotListWrapperFactory;
            }
        }
        if (factory != null) {
            log.debug("Using PKCS11SlotListWrapperFactory of type " + factory.getClass().getName());
            return factory.getInstance(pkcs11Library);
        }
        return null;
    }
}
