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

import org.cesecore.CesecoreException;

/**
 * An exception thrown when validation fails for some reason and the certificate issuance has to be aborted.
 *
 * @version $Id$
 */
public class ValidationException extends CesecoreException {

    private static final long serialVersionUID = -3123446231118692L;

    /**
     * Creates a new instance with a detail message.
     * @param message the message.
     */
    public ValidationException(String message) {
        super(message, null);
    }

    /**
     * Creates a new instance with a detail message and a root cause, mainly technical errors.
     * @param message the message.
     * @param cause the root cause.
     */
    public ValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
