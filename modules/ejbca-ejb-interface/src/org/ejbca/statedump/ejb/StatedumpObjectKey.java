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

import java.io.Serializable;

import org.apache.commons.lang.StringUtils;

/**
 * Identifies an object in EJBCA.
 *
 * @version $Id$
 */
public final class StatedumpObjectKey implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final String type;
    private final int id;
    private final String name;

    public StatedumpObjectKey(final String type, final int id, final String name) {
        this.type = type;
        this.id = id;
        this.name = name;
    }
    
    public String getType() {
        return type;
    }
    
    public int getId() {
        return id;
    }
    
    public String getName() {
        return name;
    }
    
    @Override
    public String toString() {
        return type+" "+name+" ("+id+")";
    }
    
    @Override
    public boolean equals(final Object o) {
        if (o instanceof StatedumpObjectKey) {
            final StatedumpObjectKey sc = (StatedumpObjectKey)o;
            return StringUtils.equals(sc.getType(), type) &&
                    StringUtils.equals(sc.getName(), name) &&
                    sc.getId() == id;
        }
        return false;
    }
    
    @Override
    public int hashCode() {
        return id ^ type.hashCode() ^ (name.hashCode() + 1);
    }
}
