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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;

/**
 * Primary key for HardTokenPropertyData
 */
public class HardTokenPropertyDataPK implements Serializable {

	private static final long serialVersionUID = 1L;

	public String id;
	public String property;

	public HardTokenPropertyDataPK() { }

	public HardTokenPropertyDataPK(String id, String property) {
		setId(id);
		setProperty(property);
	}

    //@Column
	public String getId() { return id; }
	public void setId(String id) { this.id = id; }
	
    //@Column
	public String getProperty() { return property; }
	public void setProperty(String property) { this.property = property; }

	public int hashCode() {
		int hashCode = 0;
		if (id != null) { hashCode += id.hashCode(); }
		if (property != null) { hashCode += property.hashCode(); }
		return hashCode;
	}

	public boolean equals(Object obj) {
		if ( obj == this ) { return true; }
		if ( !(obj instanceof HardTokenPropertyDataPK) ) { return false; }
		HardTokenPropertyDataPK pk = (HardTokenPropertyDataPK)obj;
		if ( id == null || !id.equals(pk.id) ) { return false; }
		if ( property == null || !property.equals(pk.property) ) { return false; }
		return true;
	}
}
