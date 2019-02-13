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
package org.cesecore.certificates.endentity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 
 * Constants for users and certificates. Constants for Type of user: Type is constructed as a mask
 * since one user can be of several types. To test a user type:
 * <pre>
 * if (((type & USER_ENDUSER) == USER_ENDUSER) && ((type & USER_CAADMIN) == USER_ADMINISTOR) || ...
 *    ...
 * </pre>
 * Bit usage: bits 0-7   (1:st byte):  user types bits 8-15  (2:nd byte):  unused bits 16-23 (3:rd
 * byte):  unused bits 24-30 (4:th byte):  unused Constants for certificates are simple integer
 * types. Constants for Token Types Token type is constructed of integer constants since only one
 * 
 * @version $Id$
 *
 */
public enum EndEntityTypes  { 
    INVALID(0x0, "Dummy type."),
    ENDUSER(0x1, "This is an end user certificate (default)."),
    ADMINISTRATOR(0x40, "This user is an administrator."),
    KEYRECOVERABLE(0x80, "This users keystores are key recoverable."),
    SENDNOTIFICATION(0x100, "Notification will be sent to this users emailaddress"), 
    PRINT(0x200, "Registration data will be printed for this user");
    
    private static final Map<Integer, EndEntityTypes> lookupTable;
    
    private int hexCode;
    private String description;
    
    static {
        lookupTable = new HashMap<Integer, EndEntityTypes>();
        for(EndEntityTypes type : EndEntityTypes.values()) {
            lookupTable.put(type.hexValue(), type);
        }
    }
    
    private EndEntityTypes(int hexCode, String description) {
        this.hexCode = hexCode;
        this.description = description;
    }

    /**
     * 
     * @return the hexcode value for this end entity type.
     */
    public int hexValue() {
        return hexCode;
    }
    
    public String getDescription() {
        return description;
    }
    
    public static EndEntityTypes[] getTypesFromHexCode(int hexCode) {
        List<EndEntityTypes> result = new ArrayList<EndEntityTypes>();
        for(EndEntityTypes type : EndEntityTypes.values()) {
            if(type.isContainedInType(hexCode)) {
                result.add(type);
            }
        }
        return result.toArray(new EndEntityTypes[result.size()]);
    }
    
    public static int combineAll(EndEntityTypes[] types) {
        int result = 0;
        for(EndEntityTypes type : types) {
            result = type.addTo(result);
        }
        return result;
    }
    
    /**
     * Filters this end entity type to the given parameter by performing a binary AND operation on
     * their hex values and returning whatever type which matches the result.  
     * 
     * @param otherHexCode hex code EndEntityType to filter with
     * @return the corresponding EndEntityType, or null if not found.
     */
    public boolean isContainedInType(int otherHexCode) {
        return (hexCode & otherHexCode) == hexCode; 
    }


    /**
     * Joins this end entity type to the given parameter by performing a binary OR operation on
     * their hex valyes and returning whatever type which matches the result
     * 
     * @param otherHexCode hex code of an EndEntityType to join with
     * @return the resulting amalgam 
     */
    public int addTo(int otherHexCode) {   
        return hexCode | otherHexCode;
    }
    
    /**
     * Removes this type from the given hexcode
     * 
     * @param otherHexCode the hexcode to remove this type from
     * @return the resulting hexcode
     */
    public int removeFromType(int otherHexCode) {
        return otherHexCode & ~this.hexCode;
    }
    
    /**
     * Simple utility method for creating an EndEntityType with a single type.
     * 
     * @return a new EndEntityType.
     */
    public EndEntityType toEndEntityType() {
        return new EndEntityType(this);
    }
}
