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

import javax.xml.ws.WebFault;

/**
 * An exception thrown by the isauthorized method in the EjbcaAthorization bean.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
@WebFault
public class AuthorizationDeniedException extends java.lang.Exception {
    

    private static final long serialVersionUID = 4400551462100867374L;


    /**
     * Creates a new instance of <code>AuthorizationDeniedException</code> without detail message.
     */
    public AuthorizationDeniedException() {
      super();  
    }
    
    
    /**
     * Constructs an instance of <code>AuthorizationDeniedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AuthorizationDeniedException(String msg) {
        super(msg);
    }
}
