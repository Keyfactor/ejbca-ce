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
 * An exception thrown when someone tries to access a key validator that doesn't exits.
 *
 * @version $Id: KeyValidatorDoesntExistsException.java 22117 2017-03-01 12:12:00Z anjakobs $
 */
public class KeyValidatorDoesntExistsException extends Exception {

    private static final long serialVersionUID = 4122021467195662691L;

    /**
     * Creates a new instance.
     */
    public KeyValidatorDoesntExistsException() {
        super( "Key validator does not exist in datastore.");
    }

    /**
     * Creates a new instance with the specified detail message.
     * @param message the detail message.
     */
    public KeyValidatorDoesntExistsException(final String message) {
        super(message);
    }
}
