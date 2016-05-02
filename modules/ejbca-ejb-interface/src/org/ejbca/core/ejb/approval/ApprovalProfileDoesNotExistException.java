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
package org.ejbca.core.ejb.approval;

import org.cesecore.CesecoreException;


/**
 * An exception thrown when someone tries to change an approval profile that doesn't already exits
 * 
 * @version $Id$
 */
public class ApprovalProfileDoesNotExistException extends CesecoreException {
    

    private static final long serialVersionUID = -1038676703612812109L;


    /**
     * Creates a new instance of <code>ApprovalProfileDoesntExistsException</code> without detail message.
     */
    public ApprovalProfileDoesNotExistException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>ApprovalProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ApprovalProfileDoesNotExistException(String msg) {
        super(msg);
    }
}
