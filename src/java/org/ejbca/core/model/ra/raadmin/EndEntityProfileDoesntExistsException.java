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

/**
 * An exception thrown when someone tries to add an end entity profile that already exits
 *
 * @author Philip Vendil 2002-06-13
 * @version $Id$
 */
public class EndEntityProfileDoesntExistsException extends java.lang.Exception {
    private static final long serialVersionUID = 8013494910881102216L;

    /**
     * Creates a new instance of <code>EndEntityProfileDoesntExistsException</code> without detail
     * message.
     */
    public EndEntityProfileDoesntExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>EndEntityProfileDoesntExistsException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public EndEntityProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
