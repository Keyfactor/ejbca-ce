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
package org.ejbca.ui.web.configuration.exception;

/**
 * An exception thrown when trying to change or remove a user that does not exist in the database.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class AdminDoesntExistException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of <code>AdminDoesntExistException</code> without detail message.
     */
    public AdminDoesntExistException() {
        super();
    }

    /**
     * Constructs an instance of <code>AdminDoesntExistException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public AdminDoesntExistException(String msg) {
        super(msg);
    }
}
