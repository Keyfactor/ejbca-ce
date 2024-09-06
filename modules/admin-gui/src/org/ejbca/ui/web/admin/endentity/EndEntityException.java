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
package org.ejbca.ui.web.admin.endentity;

/**
 * Exception class used when error happens in end entity creation (admin web)
 */
public class EndEntityException extends RuntimeException {
    
    private static final long serialVersionUID = 1L;

    public EndEntityException() {
        super();
    }

    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * base class <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public EndEntityException(String message) {
        super(message);
    }


    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * base class <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public EndEntityException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
