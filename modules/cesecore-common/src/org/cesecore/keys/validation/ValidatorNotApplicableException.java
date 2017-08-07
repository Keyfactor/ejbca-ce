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

import javax.ejb.ApplicationException;

import org.cesecore.CesecoreException;

/**
 * An exception thrown when someone tries validate with input that is not applicable for a specific validator.
 * For example a wrong key algorithm (i.e. try to validate an ECC key with an RSA key validator).
 *
 * @version $Id$
 */
@ApplicationException(rollback=true)
public class ValidatorNotApplicableException extends CesecoreException {

    private static final long serialVersionUID = 3339929462315318612L;

    /**
     * Creates a new instance with a detail message.
     * @param message the detail message.
     */
    public ValidatorNotApplicableException(final String message) {
        super(message);
    }
}
