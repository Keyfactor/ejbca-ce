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
 * HardTokenIssuerExistsException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package org.ejbca.core.model.hardtoken;

/**
 * An exception thrown when someone tries to remove or change a hard token issuer that doesn't exits
 *
 * @author  Philip Vendil
 * @version $Id: HardTokenIssuerDoesntExistsException.java,v 1.2 2006-02-08 07:31:49 anatom Exp $
 */
public class HardTokenIssuerDoesntExistsException extends java.lang.Exception {
    
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
