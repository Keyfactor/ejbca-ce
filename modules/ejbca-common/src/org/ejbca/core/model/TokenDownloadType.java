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

package org.ejbca.core.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Representation of token download types.
 */
public enum TokenDownloadType {
    PEM(1), PEM_FULL_CHAIN(2), PKCS7(3), P12(4), JKS(5), DER(6), BCFKS(7);
    
    private int value;
    private static final Map<String, Integer> nameIdLookupMap = new HashMap<String, Integer>();
    private static final Map<Integer, String> idNameLookupMap = new HashMap<Integer, String>();
    
    static {
        for (TokenDownloadType tokenDownloadType : TokenDownloadType.values()) {
            nameIdLookupMap.put(tokenDownloadType.name(), tokenDownloadType.value);
            idNameLookupMap.put(tokenDownloadType.value, tokenDownloadType.name());
        }
    }
    
    private TokenDownloadType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
    
    /**
     * @param tokenTypeName TokenDownloadType Enum name
     * @return Id represented by input Enum name or null if non-existent
     */
    public static Integer getIdFromName(String tokenTypeName) {
        return nameIdLookupMap.get(tokenTypeName);
    }
    
    /**
     * @param id TokenDownloadType Enum Id
     * @return String representation of the Enum Id input or null of non-existent
     */
    public static String getNameFromId(int id) {
        return idNameLookupMap.get(id);
    }
}
