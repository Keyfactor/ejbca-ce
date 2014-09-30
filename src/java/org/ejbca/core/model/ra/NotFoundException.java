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

import org.ejbca.core.EjbcaException;


/**
 * Thrown when an object cannot be found in the database and the error is not critical so we want
 * to inform the client in a nice way.
 *
 * @version $Id$
 */
@WebFault
public class NotFoundException extends EjbcaException {
 
    private static final long serialVersionUID = 1L;
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public NotFoundException(String message) {
        super(message);
    }
    public NotFoundException(String message, Throwable cause) {
        super(message);
        super.initCause(cause);
    }
}
