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
 
package org.ejbca.core.model.ra.userdatasource;

import org.ejbca.core.EjbcaException;


/**
 * Is throw when connection to a user data source have failed i some way.
 *
 * @version $Id$
 */
public class UserDataSourceConnectionException extends EjbcaException {
    
    private static final long serialVersionUID = 407640832586446989L;


    /**
     * Creates a new instance of <code>UserDataSourceConnectionException</code> without detail message.
     */
    public UserDataSourceConnectionException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UserDataSourceConnectionException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserDataSourceConnectionException(String msg) {    	
        super(msg);        
    }
}
