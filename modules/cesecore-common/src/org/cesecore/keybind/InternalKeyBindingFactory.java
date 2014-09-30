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
package org.cesecore.keybind;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;

/**
 * Factory class with an internal registry of known implementations.
 * 
 * @version $Id$
 */
public enum InternalKeyBindingFactory {
    INSTANCE;

    private final Logger log = Logger.getLogger(InternalKeyBindingFactory.class);
    private final Map<String, String> aliasToImplementationMap = new HashMap<String, String>();
    private final Map<String, String> implementationToAliasMap = new HashMap<String, String>();
    private final Map<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>> implementationPropertiesMap = new HashMap<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>>();

    private InternalKeyBindingFactory() {
        addImplementation(OcspKeyBinding.class);
        addImplementation(AuthenticationKeyBinding.class);
        // Use ServiceLoader framework to find additional available implementations
        // We add these after the built in ones, so the built in implementations can be overridden
        // TODO the above when we need to
    }

    public boolean existsTypeAlias(String alias) {
        return aliasToImplementationMap.containsKey(alias);
    }

    /**
     * Creates a new InternalKeyBinding instance.
     * 
     * @param type is the alias of the registered InternalKeyBinding's type
     * @param id is the unique identifier of this InternalKeyBinding
     * @param name is the unique name that this InternalKeyBinding will be given
     * @param status the initial status to give the InternalKeyBinding
     * @param certificateId is the certificate fingerprint (lower case) matching the mapped key pair or null
     * @param cryptoTokenId is the CryptoToken id of the container where the mapped key pair is stored
     * @param keyPairAlias is the alias of the mapped key pair in the specified CryptoToken (may not be null)
     * @param dataMap is a Map of implementation specific properties for this type of IntenalKeyBinding
     * @return a new InternalKeyBinding instance
     */
    public InternalKeyBinding create(final String type, final int id, final String name, final InternalKeyBindingStatus status,
            final String certificateId, final int cryptoTokenId, final String keyPairAlias, final LinkedHashMap<Object, Object> dataMap) {
        final String implementationClassName = aliasToImplementationMap.get(type);
        InternalKeyBinding internalKeyBinding = null;
        if (implementationClassName == null) {
            log.error("Unable to create Signer. Implementation for type '" + type + "' not found.");
        } else {
            try {
                internalKeyBinding = (InternalKeyBinding) Class.forName(implementationClassName).newInstance();
                // Ensure that fingerprint is lower case, to match items in the database
                final String certFp;
                if (certificateId != null) {
                    certFp = certificateId.toLowerCase(Locale.ENGLISH);
                } else {
                    certFp = null;
                }
                internalKeyBinding.init(id, name, status, certFp, cryptoTokenId, keyPairAlias, dataMap);
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
        Map<String, InternalKeyBindingProperty<? extends Serializable>> implementationProperties = null;
        try {
            final InternalKeyBinding temporaryInstance = c.newInstance();
            alias = temporaryInstance.getImplementationAlias();
            implementationProperties = temporaryInstance.getCopyOfProperties();
            implementationPropertyKeys = new ArrayList<String>();
            for (String name : implementationProperties.keySet()) {
                implementationPropertyKeys.add(name);
            }
        } catch (InstantiationException e) {
            log.error("Unable to create InternalKeyBinding. Could not be instantiate implementation '" + c.getName() + "'.", e);
        } catch (IllegalAccessException e) {
            log.error("Unable to create InternalKeyBinding. Not allowed to instantiate implementation '" + c.getName() + "'.", e);
        }
        if (alias != null) {
            aliasToImplementationMap.put(alias, c.getName());
            implementationToAliasMap.put(c.getName(), alias);
            implementationPropertiesMap.put(alias, Collections.unmodifiableMap((implementationProperties)));
        }
    }

    public Map<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>> getAvailableTypesAndProperties() {
        return Collections.unmodifiableMap(implementationPropertiesMap);
    }

    /**
     * Method to be used from an external environment (such as the CLI) where contextual information about a key binding 
     * implementation is not available. Will presume that all key binding properties were entered as strings, will return a
     * data wrapper that contains a map of properly casted values, and information about any values which were either unknown
     * or of an incorrect format.  
     * 
     * @param alias the alias of the key binding type to check for
     * @param propertiesMap the inputed properties, as strings
     * @return a wrapper class that contains the correctly casted values, and information about any values that were invalid.
     */
    public InternalKeyBindingPropertyValidationWrapper validateProperties(String alias, Map<String, String> propertiesMap) {
        InternalKeyBindingPropertyValidationWrapper result = new InternalKeyBindingPropertyValidationWrapper();
        Map<String, InternalKeyBindingProperty<? extends Serializable>> implementationProperties =  implementationPropertiesMap.get(alias);
        for (String key : propertiesMap.keySet()) {
            if(!implementationProperties.containsKey(key)) {
                result.addUnknownProperty(key);
                continue;
            }
            InternalKeyBindingProperty<? extends Serializable> property = implementationProperties.get(key);
            String value = propertiesMap.get(key);
            Serializable recastValue = property.valueOf(value);
            if(recastValue == null) {
                result.addInvalidValue(key, property.getType());
                continue;
            }
            result.addProperty(key, recastValue);
        }
        return result;
    }
}
