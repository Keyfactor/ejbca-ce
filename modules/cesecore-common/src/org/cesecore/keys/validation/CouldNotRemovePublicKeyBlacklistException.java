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
 * An exception thrown when it was not possible to remove from datastore the public key blacklist entry fore some reason. 
 * The object is not referenced by other objects.
 *
 * @version $Id: CouldNotRemovePublicKeyBlacklistException.java 22117 2017-04-01 12:12:00Z anjakobs $
 */
public class CouldNotRemovePublicKeyBlacklistException extends Exception {

    private static final long serialVersionUID = 4523675695735398955L;

    /**
     * Creates a new instance.
     */
    public CouldNotRemovePublicKeyBlacklistException() {
        super();
    }

    /**
     * Creates a new instance with a detail message.
     * @param message the detail message.
     */
    public CouldNotRemovePublicKeyBlacklistException(String message) {
        super(message);
    }
}
