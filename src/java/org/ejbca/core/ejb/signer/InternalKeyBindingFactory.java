/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.signer;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.signer.impl.OcspKeyBinding;

/**
 * Factory class with an internal registry of known implementations.
 * 
 * @version $Id$
 */
public enum InternalKeyBindingFactory {
    INSTANCE;
    
    private final Logger log = Logger.getLogger(InternalKeyBindingFactory.class);
    private final Map<String,String> aliasToImplementationMap = new HashMap<String,String>();
    private final Map<String,String> implementationToAliasMap = new HashMap<String,String>();
    
    private InternalKeyBindingFactory() {
        addImplementation(OcspKeyBinding.class);
        // Use ServiceLoader framework to find additional available implementations
        // We add these after the built in ones, so the built in implementations can be overridden
        // TODO ...
    }

    public InternalKeyBinding create(final String type, final int id, final String name, final InternalKeyBindingStatus status, final String certificateId,
            final int cryptoTokenId, final String keyPairAlias, final LinkedHashMap<Object, Object> dataMap) {
        final String implementationClassName = aliasToImplementationMap.get(type);
        InternalKeyBinding internalKeyBinding = null;
        if (implementationClassName == null) {
            log.error("Unable to create Signer. Implementation for type '" + type + "' not found.");
        } else {
            try {
                internalKeyBinding = (InternalKeyBinding) Class.forName(implementationClassName).newInstance();
                internalKeyBinding.init(id, name, status, certificateId, cryptoTokenId, keyPairAlias, dataMap);
            } catch (InstantiationException e) {
                log.error("Unable to create InternalKeyBinding. Could not be instantiate implementation '" + implementationClassName + "'.", e);
            } catch (IllegalAccessException e) {
                log.error("Unable to create InternalKeyBinding. Not allowed to instantiate implementation '" + implementationClassName + "'.", e);
            } catch (ClassNotFoundException e) {
                log.error("Unable to create InternalKeyBinding. Could not find implementation '" + implementationClassName + "'.", e);
            }
        }
        return internalKeyBinding;
    }

    /** @return the registered alias for the provided Signer or "null" if this is an unknown implementation. */
    public String getTypeFromImplementation(final InternalKeyBinding internalKeyBinding) {
        return String.valueOf(implementationToAliasMap.get(internalKeyBinding.getClass().getName()));
    }
    
    private void addImplementation(final Class<? extends InternalKeyBinding> c) {
        final String alias = getImplementationAlias(c);
        if (alias != null) {
            aliasToImplementationMap.put(alias, c.getName());
            implementationToAliasMap.put(c.getName(), alias);
        }
    }
    
    private String getImplementationAlias(final Class<? extends InternalKeyBinding> c) {
        try {
            return c.newInstance().getImplementationAlias();
        } catch (InstantiationException e) {
            log.error("Unable to create InternalKeyBinding. Could not be instantiate implementation '" + c.getName() + "'.", e);
        } catch (IllegalAccessException e) {
            log.error("Unable to create InternalKeyBinding. Not allowed to instantiate implementation '" + c.getName() + "'.", e);
        }
        return null;
    }
}
