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
 * An exception thrown when key validation fails for some reason and the certificate issuance has to be aborted.
 *
 * @version $Id: KeyValidationException.java 22117 2017-05-01 12:12:00Z anjakobs $
 */
public class KeyValidationException extends Exception {

    private static final long serialVersionUID = -3123446231118692L;

    /**
     * Creates a new instance with a detail message.
     * @param message the message.
     */
    public KeyValidationException(String message) {
        super(message, null);
    }

    /**
     * Creates a new instance with a detail message and a root cause, mainly technical errors.
     * @param message the message.
     * @param cause the root cause.
     */
    public KeyValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
