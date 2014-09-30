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
 
package org.ejbca.core.model.ca.publisher;

/**
 * An exception thrown when someone tries to remove or change a Publisher that doesn't exits
 *
 * @author  Philip Vendil 2003-01-20
 * @version $Id$
 */
public class PublisherDoesntExistsException extends java.lang.Exception {
    
    private static final long serialVersionUID = 8116025667365391659L;


    /**
     * Creates a new instance of <code>PublisherDoesntExistsException</code> without detail message.
     */
    public PublisherDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherDoesntExistsException(String msg) {
        super(msg);
    }
}
