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

package org.ejbca.core.ejb.ra;

/**
 * An exception thrown when someone tries to delete an end entity which is referenced by other objects, or could not be deleted otherwise.
 *
 * @version $Id: CouldNotRemoveEndEntityException.java 26057 2017-06-22 08:08:34Z anatom $
 */
public class CouldNotRemoveEndEntityException extends Exception {

    private static final long serialVersionUID = 4525925695395312951L;

    /**
     * Creates a new instance.
     */
    public CouldNotRemoveEndEntityException() {
        super("Could not remove end entity, it may still be referenced by other objects.");
    }

    /**
     * Creates a new instance with a detail message.
     * @param message the detail message.
     */
    public CouldNotRemoveEndEntityException(String message) {
        super(message);
    }
}
