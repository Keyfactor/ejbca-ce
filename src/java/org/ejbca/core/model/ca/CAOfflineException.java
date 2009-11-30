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
 
package org.ejbca.core.model.ca;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;


/**
 * An exception thrown when someone tries to use a CA that is off line
 *
 * @author  Tomas Gustavsson
 * @version $Id$
 */
public class CAOfflineException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CAOfflineException</code> without detail message.
     */
    public CAOfflineException() {
        super();
        super.setErrorCode(ErrorCode.CA_OFFLINE);
    }
    
    
    /**
     * Constructs an instance of <code>CAOfflineException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CAOfflineException(String msg) {
        super(ErrorCode.CA_OFFLINE, msg);
    }
}
