/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.acme.eab;

/**
 * Custom exception for ACME EAB message parsing.
 * 
 * @version $Id$
 */
public class AcmeEabRequestParsingException extends Exception {

    private static final long serialVersionUID = 978259700029353969L;

    /**
     * Default constructor.
     * 
     * @param message the human readable message.
     * @param cause the nested exception.
     */
    public AcmeEabRequestParsingException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Default constructor.
     * 
     * @param message the human readable message.
     */
    public AcmeEabRequestParsingException(String message) {
        super(message);
    }

}
