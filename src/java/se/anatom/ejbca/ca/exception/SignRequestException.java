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
 
package se.anatom.ejbca.ca.exception;

import se.anatom.ejbca.exception.EjbcaException;


/**
 * Error due to malformed certificate request. The cause of failure can be related to ASN.1,
 * algorithm or other
 *
 * @version $Id: SignRequestException.java,v 1.4 2004-04-16 07:38:55 anatom Exp $
 */
public class SignRequestException extends EjbcaException {
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public SignRequestException(String message) {
        super(message);
    }
}
