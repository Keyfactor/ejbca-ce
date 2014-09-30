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
package org.ejbca.ui.cli;

/**
 * Thrown if a database field was not found.
 * 
 * @version $Id$
 *
 */
public class FieldNotFoundException extends Exception {

    private static final long serialVersionUID = -8695872134807966881L;

    /**
     * @param message
     */
    public FieldNotFoundException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public FieldNotFoundException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public FieldNotFoundException(String message, Throwable cause) {
        super(message, cause);
   
    }
}
