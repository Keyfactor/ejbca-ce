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
package org.ejbca.core.protocol.cmp;

/**
 * Thrown if an invalid protection algorithm is supplied with a CMP message.
 * 
 * @version $Id$
 *
 */
public class InvalidCmpProtectionException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public InvalidCmpProtectionException() {
    }

    /**
     * @param message
     */
    public InvalidCmpProtectionException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public InvalidCmpProtectionException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public InvalidCmpProtectionException(String message, Throwable cause) {
        super(message, cause);
    }



}
