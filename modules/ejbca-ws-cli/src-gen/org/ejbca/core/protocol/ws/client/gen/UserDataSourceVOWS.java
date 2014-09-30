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
package org.ejbca.core.protocol.ws.client.gen;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Class used to represent userdatasource in the WebService API.
 * because of profilenames is used instead of id's.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class UserDataSourceVOWS implements Serializable{

	private static final long serialVersionUID = 2633423909688084030L;
    private UserDataVOWS userDataVOWS = null;
	private List<Integer> isModifyable = null;

	/**
	 * WS Constructor
	 */
	public UserDataSourceVOWS(){}

	public UserDataSourceVOWS(UserDataVOWS userDataVOWS, Set<Integer> isModifyableSet){
		this.userDataVOWS = userDataVOWS;
		this.isModifyable = new ArrayList<Integer>();
		Iterator<Integer> iter = isModifyableSet.iterator();
		while(iter.hasNext()){
			isModifyable.add(iter.next());
		}	  
	}

	/**
	 * Gets a list of modifyable fields, (Should be one of the constants
	 * of the UserDataSourceVO.ISMODIFYABLE_ or
	 * DNFieldExtractor constants defined in the AVAILABLEMODIFYABLEFIELDS array.
	 * 
	 * use the contains(Object) method do find out if a field should be modifyable or not.
	 */
	public List<Integer> getIsModifyable() {
		return isModifyable;
	}

	/**
	 * Method that shouldn't be used outside the WS framework.
	 */
	public void setIsModifyable(List<Integer> isModifyable) {
		this.isModifyable = isModifyable;
	}
	
    /**
     * 
     * @return user data connected with this instance of user data source vo
     */
	public UserDataVOWS getUserDataVOWS() {
		return userDataVOWS;
	}

	/**
	 * Method that shouldn't be used outside the WS framework.
	 */
	public void setUserDataVOWS(UserDataVOWS userDataVOWS) {
		this.userDataVOWS = userDataVOWS;
	}





}
