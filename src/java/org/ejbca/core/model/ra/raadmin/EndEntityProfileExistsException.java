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
 
package org.ejbca.core.model.ra.raadmin;

/**
 * An exception thrown when someone tries to add a profile that already exists
 *
 * @version $Id$
 */
public class EndEntityProfileExistsException extends Exception {

    private static final long serialVersionUID = 6926015866489483152L;

    /**
     * Creates a new instance of <code>EndEntityProfileExistsException</code> without detail
     * message.
     */
    public EndEntityProfileExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>EndEntityProfileExistsException</code> with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public EndEntityProfileExistsException(String msg) {
        super(msg);
    }
}
