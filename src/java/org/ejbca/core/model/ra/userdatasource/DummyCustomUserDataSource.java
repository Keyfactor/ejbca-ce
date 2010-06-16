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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;


/**
 * This is an class used for testing and example purposes.
 * I supposed to illustrate how to implement a custom userdata source to EJBCA.
 *  
 *
 * @version $Id$
 */
public class DummyCustomUserDataSource implements ICustomUserDataSource{
    		
    private static Logger log = Logger.getLogger(DummyCustomUserDataSource.class);

    /**
     * Creates a new instance of DummyCustomUserDataSource
     */
    public DummyCustomUserDataSource() {}

	/**
	 * @see org.ejbca.core.model.ra.userdatasource.ICustomUserDataSource#init(java.util.Properties)
	 */
	public void init(Properties properties) {
	  // This method sets up the communication with the publisher	
		
	  log.debug("Initializing DummyCustomUserDataSource");		
	}

	/**
	 * A dummy fetch implementation that returns a UserDataVO if the searchstring "per" is given
	 * Othervise a empty collection is returned.
	 * 
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
	 */
	public Collection fetch(Admin admin, String searchstring) throws UserDataSourceException {

		ArrayList result = new ArrayList();
		if(searchstring.equalsIgnoreCase("per")){
			UserDataVO userDataVO = new UserDataVO("PER","CN=PER,C=SE",1,"RFC822NAME=per@test.com", "per@test.com",0,1,1,1,null,null,SecConst.TOKEN_SOFT_BROWSERGEN,0,null);
			result.add(new UserDataSourceVO(userDataVO));
		}
		
		return result;
	}
	
	/**
	 * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
	 */
	public void testConnection(Admin admin) throws UserDataSourceConnectionException {
        log.debug("DummyCustomUserDataSource, Testing connection");			
	}

	
	protected void finalize() throws Throwable {
        log.debug("DummyCustomUserDataSource, closing connection");
		// This method closes the communication with the publisher.	
			
		super.finalize(); 
	}

	public boolean removeUserData(Admin admin, String searchstring, boolean removeMultipleMatch) throws UserDataSourceException {
		log.debug("DummyCustomUserDataSource, remove User Data  called with searchstring : " + searchstring);
		return true;
	}


	
}
