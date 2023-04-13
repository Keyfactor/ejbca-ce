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
package org.ejbca.core.protocol.acme.eab;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.log4j.Logger;
import org.cesecore.accounts.AccountBindingException;

/**
 * Locates all implementations of the {@link #AcmeExternalAccountBinding} 
 * interface found in the system.
 */
public enum AcmeExternalAccountBindingFactory {

    INSTANCE;

    /** Object logger. */
    private final Logger log = Logger.getLogger(AcmeExternalAccountBindingFactory.class);
    
    /** Map with type/object pairs. */
    private Map<String, AcmeExternalAccountBinding> identifierToImplementationMap = new HashMap<>();

    /**
     * Default Constructor. Locates all implementations of the 
     * {@link #AcmeExternalAccountBinding} interface.
     */
    private AcmeExternalAccountBindingFactory() {
        ServiceLoader<AcmeExternalAccountBinding> svcloader = ServiceLoader.load(AcmeExternalAccountBinding.class);
        for (AcmeExternalAccountBinding type : svcloader) {
            type.initialize();
            identifierToImplementationMap.put(type.getAccountBindingTypeIdentifier(), type);
            if (log.isDebugEnabled()) {
                log.debug("Found ACME EAB implementation '" + type.getAccountBindingTypeIdentifier() + "'.");
            }
        }
    }

    /**
     * Returns a map with all type/object pairs found in the system.
     * @return the map.
     */
    public Collection<AcmeExternalAccountBinding> getAllImplementations() {
        return identifierToImplementationMap.values();
    }

    /**
     * Returns a collection with all {@link #AcmeExternalAccountBinding} found in the system.
     * 
     * @param excludeClasses classes to be excluded.
     * @return the collection.
     */
    public Collection<AcmeExternalAccountBinding> getAllImplementations(final List<Class<?>> excludeClasses) {
        if (CollectionUtils.isNotEmpty(excludeClasses)) {
            final Collection<AcmeExternalAccountBinding> result = new ArrayList<>();
            for (AcmeExternalAccountBinding implementation : getAllImplementations()) {
                if (!excludeClasses.contains(implementation.getClass())) {
                    result.add(implementation);
                }
            }
            return result;
        } else {
            return getAllImplementations();
        }
    }

    /**
     * Returns the ACME EAB implementation for the type identifier.
     * 
     * @param identifier the type identifier, i.e. ACME_EAB_RFC_COMPLIANT.
     * @return the implementation.
     * @throws AccountBindingException if no implementation could be found.
     */
    public AcmeExternalAccountBinding getArcheType(final String identifier) throws AccountBindingException {
        try {
            return identifierToImplementationMap.get(identifier).clone();
        } catch (NullPointerException e) {
            final String message = "No ACME EAB implementation found.";
            log.warn(message);
            throw new AccountBindingException(message);
        }
    }
    
    /**
     * Returns the default ACME EAB implementation.
     * 
     * @return the implementation.
     * @throws AccountBindingException if no default implementation could be found.
     */
    public AcmeExternalAccountBinding getDefaultImplementation() throws AccountBindingException {
        for (AcmeExternalAccountBinding implementation : getAllImplementations()) {
            if (implementation.isDefault()) {
                return implementation;
            }
        }
        final String message = "No ACME EAB implementation found.";
        log.warn(message);
        throw new AccountBindingException(message);
    }
}
