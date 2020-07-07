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
package org.cesecore.certificates.ca;

import javax.ejb.ApplicationException;

import org.cesecore.CesecoreException;

/**
 * Error due to an invalid request certificate signature algorithm for a certificate.
 *
 * @version $Id$
 */
@ApplicationException(rollback=true)
public class InvalidAlgorithmException extends CesecoreException {

    private static final long serialVersionUID = 6774153561528947364L;

    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public InvalidAlgorithmException(final String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public InvalidAlgorithmException(final Exception exception) {
        super(exception);
    }

    public InvalidAlgorithmException(final String message, final Throwable exception) {
        super(message, exception);
    }
}
