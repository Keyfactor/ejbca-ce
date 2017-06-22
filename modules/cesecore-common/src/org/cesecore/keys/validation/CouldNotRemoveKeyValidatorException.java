/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

/**
 * An exception thrown when someone tries to delete a KeyValidator which is referenced by other objects (i.e. CAs).
 *
 * @version $Id$
 */
public class CouldNotRemoveKeyValidatorException extends Exception {

    private static final long serialVersionUID = 4525925695395312951L;

    /**
     * Creates a new instance.
     */
    public CouldNotRemoveKeyValidatorException() {
        super( "Could not remove key validator, it is still referenced by a CA.");
    }

    /**
     * Creates a new instance with a detail message.
     * @param message the detail message.
     */
    public CouldNotRemoveKeyValidatorException(String message) {
        super(message);
    }
}
