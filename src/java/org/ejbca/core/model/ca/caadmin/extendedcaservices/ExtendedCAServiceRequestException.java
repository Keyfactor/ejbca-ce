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

/** Error processign the extended CA Sevrice request
 * @version $Id$
 */
public class ExtendedCAServiceRequestException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>ExtendedCAServiceRequestException</code> without detail message.
     */
    public ExtendedCAServiceRequestException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>ExtendedCAServiceRequestException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ExtendedCAServiceRequestException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>ExtendedCAServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public ExtendedCAServiceRequestException(Exception e) {
        super(e);
    }
}
