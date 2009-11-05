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
 
package org.ejbca.core.model.ca.catoken;

import org.ejbca.core.EjbcaException;


/**
 * An exception thrown when authentication to HardCATokens fail.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CATokenAuthenticationFailedException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CATokenAuthenticationFailedException</code> without detail message.
     */
    public CATokenAuthenticationFailedException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CATokenAuthenticationFailedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CATokenAuthenticationFailedException(String msg) {
        super(msg);
    }
}
