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
package org.ejbca.core.model.ra.raadmin;

import javax.xml.ws.WebFault;

/**
 * An exception thrown when someone tries to add or edit an end entity that doesn't match its profile
 * profile.
 * 
 * @version $Id$
 *
 */
@WebFault
public class EndEntityProfileValidationException extends Exception {

    private static final long serialVersionUID = 1L;


    public EndEntityProfileValidationException() {
    }

    /**
     * @param message a detail message
     */
    public EndEntityProfileValidationException(String message) {
        super(message);
    }

    /**
     * @param cause an underlying exception
     */
    public EndEntityProfileValidationException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message a detail message
     * @param cause an underlying exception
     */
    public EndEntityProfileValidationException(String message, Throwable cause) {
        super(message, cause);
    }


}
