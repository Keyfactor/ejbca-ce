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
package org.ejbca.core.ejb.keybind;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.keybind.impl.AuthenticationKeyBinding;
import org.ejbca.core.ejb.keybind.impl.OcspKeyBinding;

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
    private final Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> implementationPropertiesMap =
            new HashMap<String,List<InternalKeyBindingProperty<? extends Serializable>>>();

    private InternalKeyBindingFactory() {
        addImplementation(OcspKeyBinding.class);
        addImplementation(AuthenticationKeyBinding.class);
        // Use ServiceLoader framework to find additional available implementations
        // We add these after the built in ones, so the built in implementations can be overridden
        // TODO the above when we need to
    }

    /**
     * Creates a new InternalKeyBinding instance.
     * 
     * @param type is the alias of the registered InternalKeyBinding's type
     * @param id is the unique identifier of this InternalKeyBinding
     * @param name is the unique name that this InternalKeyBinding will be given
     * @param status the initial status to give the InternalKeyBinding
     * @param certificateId is the certificate fingerprint matching the mapped key pair or null
     * @param cryptoTokenId is the CryptoToken id of the container where the mapped key pair is stored
     * @param keyPairAlias is the alias of the mapped key pair in the specified CryptoToken (may not be null)
     * @param dataMap is a Map of implementation specific properties for this type of IntenalKeyBinding
     * @return a new InternalKeyBinding instance
     */
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
        String alias = null;
        List<String> implementationPropertyKeys = null;
        List<InternalKeyBindingProperty<? extends Serializable>> implementationProperties= null;
        try {
            final InternalKeyBinding temporaryInstance = c.newInstance();
            alias = temporaryInstance.getImplementationAlias();
            implementationProperties = temporaryInstance.getCopyOfProperties();
            implementationPropertyKeys = new ArrayList<String>();
            for (InternalKeyBindingProperty<? extends Serializable> property : implementationProperties) {
                implementationPropertyKeys.add(property.getName());    
            }
        } catch (InstantiationException e) {
            log.error("Unable to create InternalKeyBinding. Could not be instantiate implementation '" + c.getName() + "'.", e);
        } catch (IllegalAccessException e) {
            log.error("Unable to create InternalKeyBinding. Not allowed to instantiate implementation '" + c.getName() + "'.", e);
        }
        if (alias != null) {
            aliasToImplementationMap.put(alias, c.getName());
            implementationToAliasMap.put(c.getName(), alias);
            implementationPropertiesMap.put(alias, Collections.unmodifiableList(implementationProperties));
        }
    }

    public Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> getAvailableTypesAndProperties() {
        return Collections.unmodifiableMap(implementationPropertiesMap);
    }
}
