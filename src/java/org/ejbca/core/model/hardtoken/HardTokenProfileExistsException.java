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
 * An exception thrown when someone tries to add a hard token profile that already exits
 *
 * @author  Philip Vendil 2003-11-26
 * @version $Id$
 */
public class HardTokenProfileExistsException extends java.lang.Exception {
    
    private static final long serialVersionUID = 458620420565675559L;


    /**
     * Creates a new instance of <code>HardTokenProfileExistsException</code> without detail message.
     */
    public HardTokenProfileExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>EHardTokenProfileExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public HardTokenProfileExistsException(String msg) {
        super(msg);
    }
}
