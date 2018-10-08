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

import java.io.Serializable;

import org.apache.commons.lang.StringUtils;

/**
 * Contains a single RoleOfPSP/roleOfPspName pair of a RolesOfPSP statement (ETSI TS 119 495). 
 * @version $Id$
 */
public final class PSD2RoleOfPSPStatement implements Serializable, Cloneable {
    
    private static final long serialVersionUID = 1L;
    
    private String oid;
    private String name ;
    
    public PSD2RoleOfPSPStatement() {};
    
    public PSD2RoleOfPSPStatement(final String oid, final String name) {
        this.oid = oid;
        this.name= name;
    }

    /** @return String with PSD2 RoleOfPspOid. Never null */
    public String getOid() {
        return oid;
    }

    /** Sets the PSD2 RoleOfPspOid (ETSI TS 119 495) */
    public void setOid(final String oid) {
        this.oid = oid;
    }

    /** @return String with PSD2 RoleOfPspName. Never null */
    public String getName() {
        return name;
    }

    /** Sets the PSD2 RoleOfPspName (ETSI TS 119 495), max 256 characters */
    public void setName(final String name) {
        this.name = name;
    }
    
    @Override
    public boolean equals(final Object other) {
        if (other instanceof PSD2RoleOfPSPStatement) {
            final PSD2RoleOfPSPStatement o = (PSD2RoleOfPSPStatement) other;
            return StringUtils.equals(oid, o.getOid()) && StringUtils.equals(name, o.getName());
        } else {
            return false;
        }
    }
    
    @Override
    public int hashCode() {
        return oid.hashCode() ^ name.hashCode();
    }
    
    @Override
    protected Object clone() throws CloneNotSupportedException {
        return new PSD2RoleOfPSPStatement(oid, name);
    }
    
    /** Output the value of this object as ; separated, this ; separation is used to read/store the value as a String
     * @return String with "oid;name"
     */
    @Override
    public String toString() {
        return oid + ";" + name;
    }
    
}
