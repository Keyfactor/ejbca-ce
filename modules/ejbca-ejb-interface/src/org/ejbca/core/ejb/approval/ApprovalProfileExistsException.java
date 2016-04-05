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
package org.ejbca.core.ejb.approval;

/**
 * An exception thrown when someone tries to add an approval profile that already exits
 */
public class ApprovalProfileExistsException extends Exception {

    private static final long serialVersionUID = -8311393401572535556L;

    /**
     * Creates a new instance of <code>ApprovalProfileExistsException</code> without detail message.
     */
    public ApprovalProfileExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>ApprovalProfileExistsException</code> with the specified detail message.
     * 
     * @param msg
     *            the detail message.
     */
    public ApprovalProfileExistsException(String msg) {
        super(msg);
    }
}
