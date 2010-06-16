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
 
package org.ejbca.core.model.ra.userdatasource;

import java.util.Collection;
import java.util.Properties;

import org.ejbca.core.model.log.Admin;





/**
 * Interface containing methods that need to be implemented in order 
 * to have a custom user data source. All Custom user data sources must implement this interface.
 * 
 * @version $Id$
 */

public interface ICustomUserDataSource {
	
	/**
	 *  Method called to all newly created IUserDataSource to set it up with
	 *  saved configuration.
	 */
	public abstract void init(Properties properties);
	
	/**
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#fetch(Admin, String)
	 */   
	public Collection fetch(Admin admin, String searchstring) throws UserDataSourceException;
	
	/**
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource#removeUserData(Admin, String, boolean)
	 */   
	public boolean removeUserData(Admin admin, String searchstring, boolean removeMultipleMatch) throws MultipleMatchException, UserDataSourceException;
	
	
	/**
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
	 */    
	public abstract void testConnection(Admin admin) throws UserDataSourceConnectionException;
	

}

