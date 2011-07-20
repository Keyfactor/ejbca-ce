/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization;

import javax.ejb.ApplicationException;
import javax.xml.ws.WebFault;

/**
 * An exception thrown by the isauthorized method in the EjbcaAthorization bean.
 *
 * Based on EJBCA version: 
 *      AuthorizationDeniedException.java 11201 2011-01-15 10:23:15Z anatom
 * Based on CESeCore version:
 *      AuthorizationDeniedException.java 439 2011-03-04 16:50:41Z tomas
 * 
 * @version $Id$
 */
@WebFault
@ApplicationException(rollback=true)  
public class AuthorizationDeniedException extends Exception {
    

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
