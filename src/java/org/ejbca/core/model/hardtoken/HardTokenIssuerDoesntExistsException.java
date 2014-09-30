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
 * An exception thrown when someone tries to remove or change a hard token issuer that doesn't exits
 *
 * @author  Philip Vendil 2003-01-20
 * @version $Id$
 */
public class HardTokenIssuerDoesntExistsException extends java.lang.Exception {
    
    private static final long serialVersionUID = 1156352149099524209L;


    /**
     * Creates a new instance of <code>HardTokenIssuerDoesntExistsException</code> without detail message.
     */
    public HardTokenIssuerDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>HardTokenIssuerDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenIssuerDoesntExistsException(String msg) {
        super(msg);
    }
}
