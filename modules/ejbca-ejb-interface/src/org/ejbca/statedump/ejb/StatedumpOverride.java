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
package org.ejbca.statedump.ejb;

/**
 * @version $Id$
 */
public class StatedumpOverride {
    
    public enum Type {
        VALUE,
        PREFIX,
        APPEND,
        REGEX;
    }

    private final Type type;
    private final Object value; // depends on value of type
    
    /** Used inside StatedumpImportOptions */
    StatedumpOverride(Type type, Object value) {
        super();
        this.type = type;
        this.value = value;
    }

    public Type getType() {
        return type;
    }

    public Object getValue() {
        return value;
    }
    
}
