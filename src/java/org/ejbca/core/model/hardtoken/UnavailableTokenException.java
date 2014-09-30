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
 * An exception thrown when issuer got a token is it's queue that isn't available to it.
 *
 * @author  Philip Vendil 2003-01-20
 * @version $Id$
 */
public class UnavailableTokenException extends java.lang.Exception {
    
    private static final long serialVersionUID = 3427797936039132710L;


    /**
     * Creates a new instance of <code>UnavailableTokenException</code> without detail message.
     */
    public UnavailableTokenException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>UnavailableTokenException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public UnavailableTokenException(String msg) {
        super(msg);
    }
}
