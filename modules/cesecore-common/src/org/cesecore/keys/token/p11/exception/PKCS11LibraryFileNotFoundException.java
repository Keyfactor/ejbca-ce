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
package org.cesecore.keys.token.p11.exception;

import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Thrown to signify that a slot was not found. Differs from {@link CryptoTokenOfflineException} by virtue of
 * the latter being thrown when a slot exists, but for some reason is unavailable.
 * 
 * @version $Id$
 *
 */
public class PKCS11LibraryFileNotFoundException extends Exception {

    private static final long serialVersionUID = 471712760739840779L;

    public PKCS11LibraryFileNotFoundException() {
        super();
    }

    public PKCS11LibraryFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public PKCS11LibraryFileNotFoundException(String message) {
        super(message);
    }

    public PKCS11LibraryFileNotFoundException(Throwable cause) {
        super(cause);
    }
}
