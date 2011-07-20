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
package org.cesecore.authorization.user;

import java.util.HashMap;
import java.util.Map;

/**
 * Based on cesecore:
 *       AccessMatchType.java 191 2011-01-28 15:12:56Z mikek
 * 
 * @version $Id$
 * 
 */
public enum AccessMatchType {

    TYPE_EQUALCASE(1000), TYPE_EQUALCASEINS(1001), TYPE_NOT_EQUALCASE(1002), TYPE_NOT_EQUALCASEINS(1003);

    private AccessMatchType(int numericValue) {
        this.numericValue = numericValue;
    }

    public int getNumericValue() {
        return numericValue;
    }

    public static AccessMatchType matchFromDatabase(int numericValue) {
        return lookup.get(numericValue);
    }
    
    private int numericValue;
    private static Map<Integer, AccessMatchType> lookup;
    
    static {
        lookup = new HashMap<Integer, AccessMatchType>();
        for(AccessMatchType accessMatchType : AccessMatchType.values()) {
            lookup.put(accessMatchType.numericValue, accessMatchType);
        }
    }

}
