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
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.persistence.Version;

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
	
	@Id
	@Column(name="pK")
	public Integer getPrimKey() { return pK; }
	public void setPrimKey(Integer primKey) { this.pK = primKey; }

	/**
	 * Method returning the newest authorizationtreeupdatenumber. Should be used after each
	 * time the authorization tree is built.
	 * @return the newest accessruleset number.
	 */
	@Column(name="authorizationTreeUpdateNumber", nullable=false)
	public int getAuthorizationTreeUpdateNumber() { return authorizationTreeUpdateNumber; }
	public void setAuthorizationTreeUpdateNumber(int authorizationTreeUpdateNumber) { this.authorizationTreeUpdateNumber = authorizationTreeUpdateNumber; }

	@Version
	@Column(name = "rowVersion", nullable = false, length = 5)
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	@Column(name = "rowProtection", length = 10*1024)
	@Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	public AuthorizationTreeUpdateData() {
		setPrimKey(AUTHORIZATIONTREEUPDATEDATA);
		setAuthorizationTreeUpdateNumber(0);
	}

	/**
	 * Method used check if a reconstruction of authorization tree is needed in the
	 * authorization beans. It is used to avoid desyncronisation of authorization structures
	 * in a distibuted environment.
	 *
	 * @param currentauthorizationtreeupdatenumber indicates which authorizationtreeupdatenumber is currently used.
	 * @return true if update is needed.
	 */
	public boolean updateNeccessary(int currentauthorizationtreeupdatenumber){
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
	public static AuthorizationTreeUpdateData findByPrimeKey(EntityManager entityManager, Integer primeKey) {
		return entityManager.find(AuthorizationTreeUpdateData.class,  primeKey);
	}
}
