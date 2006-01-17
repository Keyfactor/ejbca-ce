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
 * An exception thrown when someone tries to use a CA Token that isn't available
 *
 * @author  Philip Vendil
 * @version $Id: CATokenOfflineException.java,v 1.1 2006-01-17 20:31:51 anatom Exp $
 */
public class CATokenOfflineException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CATokenOfflineException</code> without detail message.
     */
    public CATokenOfflineException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CATokenOfflineException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CATokenOfflineException(String msg) {
        super(msg);
    }
}
