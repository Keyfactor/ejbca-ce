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
 * An exception thrown when someone tries to add a Publisher that already exits
 *
 * @version $Id$
 */
public class PublisherExistsException extends java.lang.Exception {
    
    private static final long serialVersionUID = -7316779308449035285L;


    /**
     * Creates a new instance of <code>PublisherExistsException</code> without detail message.
     */
    public PublisherExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>PublisherExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public PublisherExistsException(String msg) {
        super(msg);
    }
}
