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

package org.cesecore.certificates;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum class that stores the padding possible algorithms for PKCS#12s. OAEP is the current variant, and is required for a FIPS compatible
 * installation.  
 */
public enum KeyEncryptionPaddingAlgorithm {
	PKCS_1_5("PKCS 1.5"),
	RSA_OAEP("RSA OAEP");

    private static final Map<String, KeyEncryptionPaddingAlgorithm> lookupMap = new HashMap<>();
    
    static {
        for(KeyEncryptionPaddingAlgorithm keyEncryptionPaddingAlgorithm : KeyEncryptionPaddingAlgorithm.values()) {
            lookupMap.put(keyEncryptionPaddingAlgorithm.getName(), keyEncryptionPaddingAlgorithm);
        }
    }
    
	private final String name;

	private KeyEncryptionPaddingAlgorithm(String name) {
		this.name = name;
	}

    public String getName() {
        return name;
    }
    
    public static KeyEncryptionPaddingAlgorithm getByName(final String name) {
        KeyEncryptionPaddingAlgorithm result = lookupMap.get(name);
        if(result == null) {
            throw new IllegalStateException("Invalid name was sent as padding algorithm label, was: " + name);
        } else {
            return result;
        }
    }

}
