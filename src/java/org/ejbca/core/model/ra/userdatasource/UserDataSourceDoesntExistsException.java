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
 
/*
 * PublisherDoesntExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package org.ejbca.core.model.ra.userdatasource;

/**
 * An exception thrown when someone tries to remove or change a userdata source that doesn't exits
 *
 * @author  Philip Vendil
 * @version $Id: UserDataSourceDoesntExistsException.java,v 1.1 2006-07-20 17:47:26 herrvendil Exp $
 */
public class UserDataSourceDoesntExistsException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>UserDataSourceDoesntExistsException</code> without detail message.
     */
    public UserDataSourceDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UserDataSourceDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserDataSourceDoesntExistsException(String msg) {
        super(msg);
    }
}
