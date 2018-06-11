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
 * Thrown when a profile type does not exist.
 *
 * @version $Id: UnknownProfileTypeException.java 22117 2018-06-11 16:23:42Z andresjakobs $
 */
@WebFault
public class UnknownProfileTypeException extends EjbcaException {
 
    private static final long serialVersionUID = 1L;
    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * base class <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public UnknownProfileTypeException(String message) {
        super(message);
    }
    public UnknownProfileTypeException(String message, Throwable cause) {
        super(message);
        super.initCause(cause);
    }
}
