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
 
/*
 * AdminExistsException.java
 *
 * Created on den 28 mars 2002, 16:47
 */
package org.ejbca.ui.web.admin.configuration;

/**
 * An exception thown when trying to add a user to the database that already exists.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class AdminExistsException extends java.lang.Exception {
	private static final long serialVersionUID = 1L;

	/**
     * Creates a new instance of <code>AdminExistsException</code> without detail message.
     */
    public AdminExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>AdminExistsException</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public AdminExistsException(String msg) {
        super(msg);
    }
}
