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
package org.cesecore.certificates.endentity;

import java.io.Serializable;
import java.security.InvalidParameterException;

/**
 * This class basically wraps an int value, manipulating it using various EndEntityTypes. 
 * 
 * @version $Id$
 *
 */
public class EndEntityType implements Serializable{

    private static final long serialVersionUID = 730921129476820912L;
    private int type = EndEntityTypes.INVALID.hexValue();
    
    /**
     * Creates an EndEntityType of type USER_INVALID (0x0)
     */
    public EndEntityType() {
        this.type = EndEntityTypes.INVALID.hexValue();
    }
    
    /**
     * Creates an EndEntityType of the type given in the constructor.
     * 
     * @param type Type of end entity for this EndEntityType to wrap. May not be null. 
     */
    public EndEntityType(EndEntityTypes type) {
        if(type == null) {
            throw new InvalidParameterException("Cannot create an EndEntityType with input parameter null");
        }
        this.type = type.hexValue();
    }
    
    /**
     * Creates an EndEntityType using a known type. Value is never checked, so may give unexpected results if not used properly. 
     * 
     * @param type a known hex value to set as type.
     */
    public EndEntityType(int type) {
        this.type = type;
    }
    
    /**
     * Creates an amalgam of all types given as parameters using binary OR on their hex values.   
     * 
     * @param type First type to add. Separate parameter to avoid empty instantiation. 
     * @param types varargs list of types. 
     */
    public EndEntityType(EndEntityTypes ... types) {
        if(types.length == 0) {
            throw new InvalidParameterException("Cannot create an EndEntityType with input parameter null");
        }
        this.type = 0;
        for(EndEntityTypes endEntityType : types) {
            this.type = endEntityType.addTo(this.type);
        }
    }
    
    /**
     * Checks that the wrapped type is this type and ONLY this type.
     * 
     * @param endEntityTypes a type to check against
     * @return true if the wrapped type is this type and only this type.
     */
    public boolean isType(final EndEntityTypes endEntityTypes) {
        return type == endEntityTypes.hexValue();
    }
    
    /**
     * Checks if this {@link EndEntityType} contains the given type. 
     * 
     * @param endEntityType a type to check for
     * @return true if the given type is member in this type.
     */
    public boolean contains(final EndEntityTypes endEntityType) {
        return endEntityType.isContainedInType(type);
    }
    
    /**
     * Adds the given type to this type.
     * 
     * @param endEntityType a type to add.
     */
    public void addType(final EndEntityTypes endEntityType) {
        type = endEntityType.addTo(type);
    }
    
    /**
     * Removes the given type from this type.
     * 
     * @param endEntityType a type to remove.
     */
    public void removeType(final EndEntityTypes endEntityType) {
        type = endEntityType.removeFromType(type);
    }
    
    public int getHexValue() {
        return type;
    }
}
