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


/**
 * An exception thrown when someone tries to change a CA that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id: CADoesntExistsException.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class CADoesntExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CADoesntExistsException</code> without detail message.
     */
    public CADoesntExistsException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CADoesntExistsException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>CAProfileDoesntExistsException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CADoesntExistsException(Exception e) {
        super(e);
    }
}
