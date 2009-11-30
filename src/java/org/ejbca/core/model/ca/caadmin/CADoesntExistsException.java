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
 
package org.ejbca.core.model.ca.caadmin;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;


/**
 * An exception thrown when someone tries to change a CA that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CADoesntExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CADoesntExistsException</code> without detail message.
     */
    public CADoesntExistsException() {
        super(ErrorCode.CA_NOT_EXISTS);
    }
        
    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CADoesntExistsException(String msg) {
        super(ErrorCode.CA_NOT_EXISTS, msg);
    }

    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CADoesntExistsException(Exception e) {
        super(e);
    }
}
