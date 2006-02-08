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
 * UnavalableTokenException.java
 *
 * Created on 20 januari 2003, 21:29
 */

package org.ejbca.core.model.hardtoken;

/**
 * An exception thrown when issuer got a token is it's queue that isn't available to it.
 *
 * @author  Philip Vendil
 * @version $Id: UnavailableTokenException.java,v 1.2 2006-02-08 07:31:49 anatom Exp $
 */
public class UnavailableTokenException extends java.lang.Exception {
    
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
