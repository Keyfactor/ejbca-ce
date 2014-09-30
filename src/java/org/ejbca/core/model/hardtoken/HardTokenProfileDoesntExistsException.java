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
 
package org.ejbca.core.model.hardtoken;

/**
 * An exception thrown when someone tries to remove or change a hard token profile that doesn't exits
 *
 * @author  Philip Vendil 2003-01-20
 * @version $Id$
 */
public class HardTokenProfileDoesntExistsException extends java.lang.Exception {
    
    private static final long serialVersionUID = 4861014979943948334L;


    /**
     * Creates a new instance of <code>HardTokenIssuerDoesntExistsException</code> without detail message.
     */
    public HardTokenProfileDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>HardTokenIssuerDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
