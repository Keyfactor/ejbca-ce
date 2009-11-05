/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.caadmin;

import org.ejbca.core.EjbcaException;


/**
 * Error due to an invalid request validity period for a certificate.
 *
 * @version $Id$
 */
public class IllegalValidityException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalValidityException(String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalValidityException(Exception exception) {
        super(exception);
    }
}
