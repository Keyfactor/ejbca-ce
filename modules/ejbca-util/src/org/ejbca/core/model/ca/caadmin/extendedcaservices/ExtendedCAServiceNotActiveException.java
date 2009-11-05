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
 

package org.ejbca.core.model.ca.caadmin.extendedcaservices;

/**
 * @version $Id$
 */
public class ExtendedCAServiceNotActiveException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>ExtendedCAServiceNotActiveException</code> without detail message.
     */
    public ExtendedCAServiceNotActiveException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>ExtendedCAServiceNotActiveException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IllegalExtendedServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(Exception e) {
        super(e);
    }
}
