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

package org.ejbca.core.model.ra;

import javax.xml.ws.WebFault;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Exception thrown when a revocation request for an already revoket object is requested.
 */
@WebFault
public class AlreadyRevokedException extends EjbcaException {
    
	private static final long serialVersionUID = 2290871200008158996L;


    /**
     * Creates a new instance of <code>AlreadyRevokedException</code> without detail message.
     */
	public AlreadyRevokedException() {
		super();
        super.setErrorCode(ErrorCode.ALREADY_REVOKED);
    }
	
	
	/**
     * Creates a new instance of AlreadyRevokedException
     *
     * @param message error message
     */
    public AlreadyRevokedException(String message) {
        super(ErrorCode.ALREADY_REVOKED,message);
    }
    
}
