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
 * An exception thrown when admin is not authorized to a resource.
 *
 * @version $Id$
 */
@WebFault
@ApplicationException(rollback=true)  
public class AuthorizationDeniedException extends Exception {
    

    private static final long serialVersionUID = 4400551462100867374L;


    /**
     * Creates a new instance without detail message.
     */
    public AuthorizationDeniedException() {
      super();  
    }
    
    
    /**
     * Constructs an instance with the specified detail message.
     * @param msg the detail message.
     */
    public AuthorizationDeniedException(String msg) {
        super(msg);
    }
}
