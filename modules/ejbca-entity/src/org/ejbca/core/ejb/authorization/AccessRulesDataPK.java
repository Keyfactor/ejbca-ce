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

import org.ejbca.core.model.authorization.AccessRule;

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
public class AccessRulesDataPK implements Serializable {

	private static final long serialVersionUID = 1L;

	public int primKey;

	public AccessRulesDataPK(String admingroupname, int caid, AccessRule accessrule) {
		final int adminGroupNameHash = admingroupname == null ? 0 : admingroupname.hashCode();
		final int accessRuleHash = accessrule.getAccessRule() == null ? 0 : accessrule.getAccessRule().hashCode();
		this.primKey = adminGroupNameHash ^ caid ^ accessRuleHash;
	}

	public AccessRulesDataPK() { }

	@Column(name="pK")
	public int getPrimKey()	{ return primKey; }
	public void setPrimKey(int primKey) { this.primKey = primKey; }

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(java.lang.Object otherOb) {
		if (!(otherOb instanceof AccessRulesDataPK)) {
			return false;
		}
		AccessRulesDataPK other = (AccessRulesDataPK) otherOb;
		return (this.primKey==other.primKey);
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.primKey;
	}
}
