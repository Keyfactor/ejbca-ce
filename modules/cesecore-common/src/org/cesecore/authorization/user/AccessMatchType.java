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
 * @version $Id$
 * 
 */
public enum AccessMatchType {

    TYPE_UNUSED(0),
    TYPE_EQUALCASE(1000),
    /** Case insensitive. Can be used for textual match values, e.g. a Common Name. Do <b>NOT</b> use with serial numbers (a change since 6.8.0)  */
    TYPE_EQUALCASEINS(1001),
    @Deprecated
    TYPE_NOT_EQUALCASE(1002),
    @Deprecated
    TYPE_NOT_EQUALCASEINS(1003),
    @Deprecated
    TYPE_NONE(1999);

    private AccessMatchType(int numericValue) {
        this.numericValue = numericValue;
    }

    public int getNumericValue() {
        return numericValue;
    }

    public static AccessMatchType matchFromDatabase(int numericValue) {
        return databaseLookup.get(numericValue);
    }
    
    public static AccessMatchType matchFromName(String name) {
        return nameLookup.get(name);
    }

    private int numericValue;
    private static Map<Integer, AccessMatchType> databaseLookup;
    private static Map<String, AccessMatchType> nameLookup;

    static {
        databaseLookup = new HashMap<Integer, AccessMatchType>();
        nameLookup = new HashMap<String, AccessMatchType>();
        for (AccessMatchType accessMatchType : AccessMatchType.values()) {
            databaseLookup.put(accessMatchType.numericValue, accessMatchType);
            nameLookup.put(accessMatchType.name(), accessMatchType);
        }
    }

}
