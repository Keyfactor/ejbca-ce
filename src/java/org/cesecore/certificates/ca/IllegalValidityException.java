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

import org.cesecore.CesecoreException;



/**
 * Error due to an invalid request validity period for a certificate.
 *
 * Based on EJBCA version: IllegalValidityException.java 8854 2010-03-30 15:55:35Z anatom
 * 
 * @version $Id: IllegalValidityException.java 158 2011-01-26 14:48:51Z mikek $
 */
public class IllegalValidityException extends CesecoreException {
 
    private static final long serialVersionUID = 6774153561528947364L;
  
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalValidityException(final String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalValidityException(final Exception exception) {
        super(exception);
    }
}
