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

import javax.xml.ws.WebFault;

import org.ejbca.core.EjbcaException;


/**
 * Is thrown when error occurred when searching or retrieving userdata 
 *
 * @version $Id$
 */
@WebFault
public class UserDataSourceException extends EjbcaException {
    
    private static final long serialVersionUID = -7910687478479123115L;


    /**
     * Creates a new instance of <code>UserDataSourceException</code> without detail message.
     */
    public UserDataSourceException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UserDataSourceException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UserDataSourceException(String msg) {
        super(msg);
    }
}
