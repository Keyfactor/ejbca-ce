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
 * HardTokenProfileExistsException.java
 *
 * Created on 26 november 2003, 21:29
 */

package org.ejbca.core.model.hardtoken;

/**
 * An exception thrown when someone tries to add a hard token profile that already exits
 *
 * @author  Philip Vendil
 * @version $Id: HardTokenProfileExistsException.java,v 1.2 2006-02-08 07:31:49 anatom Exp $
 */
public class HardTokenProfileExistsException extends java.lang.Exception {
    
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
