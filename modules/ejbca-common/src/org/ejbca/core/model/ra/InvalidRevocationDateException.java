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
 * Exception thrown 
 */
@WebFault
public class InvalidRevocationDateException extends EjbcaException {
    
	private static final long serialVersionUID = 1L;


    /**
     * Creates a new instance without detail message.
     */
	public InvalidRevocationDateException() {
		super();
        super.setErrorCode(ErrorCode.INVALID_REVOCATION_DATE);
    }
	
	
	/**
     * Creates a new instance of InvalidRevocationDateException
     *
     * @param message error message
     */
    public InvalidRevocationDateException(String message) {
        super(ErrorCode.INVALID_REVOCATION_DATE,message);
    }
    
}
