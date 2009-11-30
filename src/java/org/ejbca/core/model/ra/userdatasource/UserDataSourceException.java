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

import org.ejbca.core.EjbcaException;


/**
 * Is thrown when error occured when searching or retriving userdata 
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class UserDataSourceException extends EjbcaException {
    
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
