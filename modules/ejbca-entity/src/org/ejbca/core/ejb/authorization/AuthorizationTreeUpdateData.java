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
import javax.persistence.Table;

/**
 * @version $Id$
 */
@Entity
@Table(name="AuthorizationTreeUpdateData")
public class AuthorizationTreeUpdateData implements Serializable {

	private static final long serialVersionUID = 1L;
	public static final Integer AUTHORIZATIONTREEUPDATEDATA = new Integer(1);

	private Integer pK;
	private int authorizationTreeUpdateNumber;
	
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

	public static AuthorizationTreeUpdateData findByPrimeKey(EntityManager entityManager, Integer primeKey) {
		return entityManager.find(AuthorizationTreeUpdateData.class,  primeKey);
	}
}
