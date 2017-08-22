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
package org.ejbca.util.mail;

/**
 * Generic exception for mail handling.
 * 
 * @version $Id$
 *
 */
public class MailException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public MailException() {
    }

    /**
     * @param message
     */
    public MailException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public MailException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public MailException(String message, Throwable cause) {
        super(message, cause);
    }

}
