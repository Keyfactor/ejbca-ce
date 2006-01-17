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
 * AuthorizationDeniedException.java
 *
 * Created on den 1 april 2002, 12:37
 */

package org.ejbca.core.model.authorization;

/**
 * An exception thrown by the authenticate method in the EjbcaAthorization bean when authentication of a given certificate failed.
 *
 * @author  Philip Vendil
 */
public class AuthenticationFailedException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>AuthenticationDeniedException</code> without detail message.
     */
    public AuthenticationFailedException() {
      super();  
    }
    
    
    /**
     * Constructs an instance of <code>AuthenticationDeniedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AuthenticationFailedException(String msg) {
        super(msg);
    }
}
