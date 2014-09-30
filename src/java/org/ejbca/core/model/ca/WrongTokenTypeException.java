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
 
package org.ejbca.core.model.ca;

import org.ejbca.core.EjbcaException;



/**
 * Error due to wrong token (user-gen, p12 etc)
 *
 * @version $Id$
 */
public class WrongTokenTypeException extends EjbcaException {

    private static final long serialVersionUID = -5521689458199668528L;
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public WrongTokenTypeException(String message) {
        super(message);
    }
    /**
     * Constructs an instance of <code>WrongTokenTypeException</code> with the specified cause.
     * @param msg the detail message.
     */
    public WrongTokenTypeException(Exception e) {
        super(e);
    }
}
