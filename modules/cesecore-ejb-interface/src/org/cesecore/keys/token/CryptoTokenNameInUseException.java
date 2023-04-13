/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

/**
 * An exception thrown when someone tries to create a CryptoToken with an existing name.
 *
 * @version $Id$
 */
public class CryptoTokenNameInUseException extends CesecoreException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of <code>CryptoTokenNameInUseException</code> without detail message.
     */
    public CryptoTokenNameInUseException() {
        super();
        super.setErrorCode(ErrorCode.CRYPTOTOKEN_NAME_IN_USE);
    }

    /**
     * Constructs an instance of <code>CryptoTokenNameInUseException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CryptoTokenNameInUseException(String msg) {
        super(ErrorCode.CRYPTOTOKEN_NAME_IN_USE, msg);
    }

    /**
     * Constructs an instance of <code>CryptoTokenNameInUseException</code> with the specified detail message.
     * @param exception the exception that caused this
     */
    public CryptoTokenNameInUseException(Exception exception) {
        super(ErrorCode.CRYPTOTOKEN_NAME_IN_USE, exception);
    }

    /**
     * Constructs an instance of <code>CryptoTokenNameInUseException</code> with the specified detail message.
     * @param msg the detail message.
     * @param exception the exception that caused this
     */
    public CryptoTokenNameInUseException(String msg, Exception e) {
        super(ErrorCode.CRYPTOTOKEN_NAME_IN_USE, msg, e);
    }
}
