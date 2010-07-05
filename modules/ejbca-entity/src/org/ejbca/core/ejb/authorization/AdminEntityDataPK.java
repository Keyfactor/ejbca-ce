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

package org.ejbca.core.ejb.authorization;

import java.io.Serializable;

import javax.persistence.Column;

/**
 * The current pk in AdminEntityData and AccessRulesData is a mix of integer pk and 
 * constraints and actually works fine. 
 * It's used like a primitive int primary key in the db, but embeds logic for 
 * enforcing constraints, which would otherwise have to be programatically added to the beans.
 * If needed it can easily be replaced with an int pk and programatic logic to handle 
 * constraints. From the database view the pk is just an int.
 * 
 * @version $Id$
 */
public class AdminEntityDataPK implements Serializable {

	private static final long serialVersionUID = 1L;

	public int primeKey;

	public AdminEntityDataPK(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue) {
		final int adminGroupNameHash = admingroupname == null ? 0 : admingroupname.hashCode();
		final int matchValueHash = matchvalue == null ? 0 : matchvalue.hashCode();
		this.primeKey = adminGroupNameHash ^ caid ^ matchwith ^ matchValueHash ^ matchtype;
	}

	public AdminEntityDataPK() { }

	@Column(name="pK")
	public int getPrimeKey() { return primeKey; }
	public void setPrimeKey(int primeKey) { this.primeKey = primeKey; }

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(java.lang.Object otherOb) {
		if (!(otherOb instanceof AdminEntityDataPK)) {
			return false;
		}
		AdminEntityDataPK other = (AdminEntityDataPK) otherOb;
		return (this.primeKey == other.primeKey);
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.primeKey;
	}
}
