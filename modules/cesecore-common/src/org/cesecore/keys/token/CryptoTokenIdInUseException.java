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
package org.cesecore.keys.token;

/**
 * Thrown when trying to create a crypto token with a specific ID that is already in use.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenIdInUseException extends Exception {

    private static final long serialVersionUID = -7489643048484029833L;

    public CryptoTokenIdInUseException() {
        super();
    }

    public CryptoTokenIdInUseException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoTokenIdInUseException(String message) {
        super(message);
    }

    public CryptoTokenIdInUseException(Throwable cause) {
        super(cause);
    }

}
