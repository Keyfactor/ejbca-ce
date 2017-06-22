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

package org.ejbca.core.ejb.ca.validation;

/**
 * An exception thrown when someone tries to access a public key blacklist entry that doesn't exits.
 *
 * @version $Id$
 */
public class PublicKeyBlacklistDoesntExistsException extends Exception {

    private static final long serialVersionUID = 412202146316881114L;

    /**
     * Creates a new instance.
     */
    public PublicKeyBlacklistDoesntExistsException() {
        super( "Public key blacklist does not exist in datastore.");
    }

    /**
     * Creates a new instance with the specified detail message.
     * @param message the detail message.
     */
    public PublicKeyBlacklistDoesntExistsException(final String message) {
        super(message);
    }
}
