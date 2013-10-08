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

package org.ejbca.core.protocol.cmp.authentication;

import javax.ejb.ApplicationException;
import javax.xml.ws.WebFault;

/**
 * An exception thrown by the verification method in the ICmpAuthenticationModule.
 *
 * @version $Id$
 */
@WebFault
@ApplicationException(rollback=true)  
public class CMPAuthenticationException extends Exception {
    

    private static final long serialVersionUID = 4400551462100867374L;


    /**
     * Creates a new instance of <code>AuthorizationDeniedException</code> without detail message.
     */
    public CMPAuthenticationException() {
      super();  
    }
    
    
    /**
     * Constructs an instance of <code>AuthorizationDeniedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CMPAuthenticationException(String msg) {
        super(msg);
    }
}
