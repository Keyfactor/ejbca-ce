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
 
package se.anatom.ejbca.admin;

/**
 * Exception throws when an error occurs in an Admin Command (IadminCommand)
 *
 * @version $Id: ErrorAdminCommandException.java,v 1.3 2004-04-16 07:38:57 anatom Exp $
 */
public class ErrorAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {
    /**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param message error message
     */
    public ErrorAdminCommandException(String message) {
        super(message);
    }

    /**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param exception root cause of error
     */
    public ErrorAdminCommandException(Exception exception) {
        super(exception);
    }
}
