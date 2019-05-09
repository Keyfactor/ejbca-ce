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

import org.ejbca.core.EjbcaException;


/**
 * Thrown when a publisher is unable to run due to the CA being in a null-state.
 *
 * @version $Id: PublisherConnectionException.java 30196 2018-10-25 16:34:42Z samuellb $
 */
public class FatalPublisherConnectionException extends EjbcaException {
    
    private static final long serialVersionUID = -7709220093705684945L;


    /**
     * Creates a new instance of <code>FatalPublisherConnectionException</code> without detail message.
     */
    public FatalPublisherConnectionException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>FatalPublisherConnectionException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public FatalPublisherConnectionException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>FatalPublisherConnectionException</code> with the specified detail message and cause.
     * @param msg the detail message.
     * @param cause Exception that caused the FatalPublisherConnectionException.
     */
    public FatalPublisherConnectionException(final String msg, final Throwable cause) {
        super(msg, cause);
    }
}
