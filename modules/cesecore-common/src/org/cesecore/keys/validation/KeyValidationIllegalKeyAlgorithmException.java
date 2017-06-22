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
 * An exception thrown when someone tries validate a key with a wrong key algorithm (i.e. try to validate an ECC key with an RSA key validator).
 *
 * @version $Id$
 */
public class KeyValidationIllegalKeyAlgorithmException extends KeyValidationException {

    private static final long serialVersionUID = 3339929462315318612L;

    /**
     * Creates a new instance with a detail message.
     * @param message the detail message.
     */
    public KeyValidationIllegalKeyAlgorithmException(final String message) {
        super(message);
    }
}
