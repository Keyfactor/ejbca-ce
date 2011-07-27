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
package org.cesecore.authorization.rules;

import java.util.HashMap;
import java.util.Map;

/**
 * Based on cesecore version:
 *      AccessRuleState.java 229 2011-02-03 10:23:18Z mikek
 * 
 * @version $Id$
 * 
 */
public enum AccessRuleState {
    RULE_NOTUSED("UNUSED", 0), RULE_ACCEPT("ACCEPT", 1), RULE_DECLINE("DECLINE", 2);
  
    private AccessRuleState(String name, int databaseValue) {
        this.name = name;
        this.databaseValue = databaseValue;
    }

    public String getName() {
        return name;
    }

    public int getDatabaseValue() {
        return databaseValue;
    } 
    
    public static AccessRuleState matchDatabaseValue(Integer value) {
        return map.get(value);
    }
    
    private String name;
    private int databaseValue;
    private static Map<Integer, AccessRuleState> map = new HashMap<Integer, AccessRuleState>();
    
    static {
        for(AccessRuleState state : AccessRuleState.values()) {
            map.put(state.getDatabaseValue(), state);
        }
    }
    

    
    
}
