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
 
package se.anatom.ejbca;

/** Compount primary key for property entities.
 *
 * @version $Id: PropertyEntityPK.java,v 1.6 2004-04-16 07:39:01 anatom Exp $
 */

public final class PropertyEntityPK implements java.io.Serializable {

    public String id;
    public String property;

    public PropertyEntityPK(String id, String property) {
        this.id = id;
        this.property=property;
    }
    
    public String getId() {
        return id;
    }
    public String getProperty() {
        return property;
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object other) {
        if (other instanceof PropertyEntityPK) {
           return ( (id.equals(((PropertyEntityPK)other).id)) &&
               (property.equals(((PropertyEntityPK)other).property)) );
        }
        return false;
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.id.hashCode()^this.property.hashCode();
    }

}

