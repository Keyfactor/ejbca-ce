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
import org.ejbca.core.ejb.signer.impl.OcspSignerMapping;

/**
 * Factory class with an internal registry of known Signer implementations.
 * 
 * @version $Id$
 */
public enum SignerMappingFactory {
    INSTANCE;
    
    private final Logger log = Logger.getLogger(SignerMappingFactory.class);
    private final Map<String,String> aliasToImplementationMap = new HashMap<String,String>();
    private final Map<String,String> implementationToAliasMap = new HashMap<String,String>();
    
    private SignerMappingFactory() {
        addSignerMapping(OcspSignerMapping.class);
        // Use ServiceLoader framework to find additional available implementations
        // We add these after the built in ones, so the built in SignerMappings can be overridden
        // TODO ...
    }

    public SignerMapping createSignerMapping(final String type, final int signerMappingId, final String name, final SignerMappingStatus status, final String certificateId,
            final int cryptoTokenId, final String keyPairAlias, final LinkedHashMap<Object, Object> dataMap) {
        final String implementationClassName = aliasToImplementationMap.get(type);
        SignerMapping signerMapping = null;
        if (implementationClassName == null) {
            log.error("Unable to create Signer. Implementation for type '" + type + "' not found.");
        } else {
            try {
                signerMapping = (SignerMapping) Class.forName(implementationClassName).newInstance();
                signerMapping.init(signerMappingId, name, status, certificateId, cryptoTokenId, keyPairAlias, dataMap);
            } catch (InstantiationException e) {
                log.error("Unable to create SignerMapping. Could not be instantiate implementation '" + implementationClassName + "'.", e);
            } catch (IllegalAccessException e) {
                log.error("Unable to create SignerMapping. Not allowed to instantiate implementation '" + implementationClassName + "'.", e);
            } catch (ClassNotFoundException e) {
                log.error("Unable to create SignerMapping. Could not find implementation '" + implementationClassName + "'.", e);
            }
        }
        return signerMapping;
    }

    /** @return the registered alias for the provided Signer or "null" if this is an unknown implementation. */
    public String getTypeFromImplementation(final SignerMapping signerMapping) {
        return String.valueOf(implementationToAliasMap.get(signerMapping.getClass().getName()));
    }
    
    private void addSignerMapping(final Class<? extends SignerMapping> c) {
        final String alias = getSignerMappingAlias(c);
        if (alias != null) {
            aliasToImplementationMap.put(alias, c.getName());
            implementationToAliasMap.put(c.getName(), alias);
        }
    }
    
    private String getSignerMappingAlias(final Class<? extends SignerMapping> c) {
        try {
            return c.newInstance().getSignerMappingAlias();
        } catch (InstantiationException e) {
            log.error("Unable to create SignerMapping. Could not be instantiate implementation '" + c.getName() + "'.", e);
        } catch (IllegalAccessException e) {
            log.error("Unable to create SignerMapping. Not allowed to instantiate implementation '" + c.getName() + "'.", e);
        }
        return null;
    }
}
