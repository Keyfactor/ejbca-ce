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
package org.ejbca.ui.web.admin.configuration;

/**
 * Thrown to indicate that a custom extension property value is invalid.
 * 
 * @version $Id$
 *
 */
public class InvalidCustomExtensionPropertyException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public InvalidCustomExtensionPropertyException() {
    }

    /**
     * @param message
     */
    public InvalidCustomExtensionPropertyException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public InvalidCustomExtensionPropertyException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public InvalidCustomExtensionPropertyException(String message, Throwable cause) {
        super(message, cause);
    }

}
