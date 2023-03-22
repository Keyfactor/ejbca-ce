/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys.token.pkcs11;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Thrown to signify that a slot was not found. Differs from {@link CryptoTokenOfflineException} by virtue of
 * the latter being thrown when a slot exists, but for some reason is unavailable.
 * 
 *
 */
public class NoSuchSlotException extends Exception {

    private static final long serialVersionUID = -1943802946146748726L;

    public NoSuchSlotException() {
        super();
    }

    public NoSuchSlotException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSuchSlotException(String message) {
        super(message);
    }

    public NoSuchSlotException(Throwable cause) {
        super(cause);
    }

}
