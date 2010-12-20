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

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Table;

/**
 * @version $Id$
 */
@Entity
@Table(name="AuthorizationTreeUpdateData")
public class AuthorizationTreeUpdateData implements Serializable {

	private static final long serialVersionUID = 1L;
	public static final Integer AUTHORIZATIONTREEUPDATEDATA = Integer.valueOf(1);

	private Integer pK;
	private int authorizationTreeUpdateNumber;
	private int rowVersion = 0;
	private String rowProtection;
	
	public AuthorizationTreeUpdateData() {
		setPrimKey(AUTHORIZATIONTREEUPDATEDATA);
		setAuthorizationTreeUpdateNumber(0);
	}

	//@Id @Column
	public Integer getPrimKey() { return pK; }
	public final void setPrimKey(final Integer primKey) { this.pK = primKey; }

	/**
	 * Method returning the newest authorizationtreeupdatenumber. Should be used after each
	 * time the authorization tree is built.
	 * @return the newest accessruleset number.
	 */
	//@Column
	public int getAuthorizationTreeUpdateNumber() { return authorizationTreeUpdateNumber; }
	public void setAuthorizationTreeUpdateNumber(int authorizationTreeUpdateNumber) { this.authorizationTreeUpdateNumber = authorizationTreeUpdateNumber; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	/**
	 * Method used check if a reconstruction of authorization tree is needed in the
	 * authorization beans. It is used to avoid desyncronisation of authorization structures
	 * in a distibuted environment.
	 *
	 * @param currentauthorizationtreeupdatenumber indicates which authorizationtreeupdatenumber is currently used.
	 * @return true if update is needed.
	 */
	public boolean updateNeccessary(final int currentauthorizationtreeupdatenumber){
		return getAuthorizationTreeUpdateNumber() != currentauthorizationtreeupdatenumber;
	}

	/**
	 * Method incrementing the authorizationtreeupdatenumber and thereby signaling
	 * to other beans that they should reconstruct their accesstrees.
	 */
	public void incrementAuthorizationTreeUpdateNumber(){
		setAuthorizationTreeUpdateNumber(getAuthorizationTreeUpdateNumber() +1);
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static AuthorizationTreeUpdateData findByPrimeKey(final EntityManager entityManager, final Integer primeKey) {
		return entityManager.find(AuthorizationTreeUpdateData.class,  primeKey);
	}
}
