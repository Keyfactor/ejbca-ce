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
 * Exception throws when illegal parameters are issued for an Admin Command (IadminCommand)
 *
 * @version $Id: IllegalAdminCommandException.java,v 1.3 2004-04-16 07:38:57 anatom Exp $
 */
public class IllegalAdminCommandException extends se.anatom.ejbca.exception.EjbcaException {
    /**
     * Creates a new instance of IllegalAdminCommandException
     *
     * @param message error message
     */
    public IllegalAdminCommandException(String message) {
        super(message);
    }
}
