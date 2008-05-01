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
 * An exception thrown when someone tries to change or create a CA that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CAExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CAExistsException</code> without detail message.
     */
    public CAExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CAExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CAExistsException(String msg) {
        super(msg);
    }
}
