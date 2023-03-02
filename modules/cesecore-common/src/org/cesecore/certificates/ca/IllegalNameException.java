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

import com.keyfactor.CesecoreException;



/**
 * Error due to an invalid request name for a certificate.
 *
 */
@ApplicationException(rollback=true) 
public class IllegalNameException extends CesecoreException {
 
    private static final long serialVersionUID = 6774153561528947364L;
  
    /**
     * Constructor used to create exception with an error message. Calls the same constructor in
     * baseclass <code>CesecoreException</code>.
     *
     * @param message Human readable error message, can not be NULL.
     */
    public IllegalNameException(final String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>CesecoreException</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalNameException(final Exception exception) {
        super(exception);
    }
    /**
     * Constructor used to create exception with a message and an embedded exception.
     * Calls the same constructor in baseclass <code>CesecoreException</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalNameException(final String message, final Exception exception) {
        super(message, exception);
    }
}
