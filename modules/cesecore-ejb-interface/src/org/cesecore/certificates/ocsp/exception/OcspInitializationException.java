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
package org.cesecore.certificates.ocsp.exception;

/**
 * Thrown when an error is encountered while starting OCSP.  
 * 
 * @version $Id$
 *
 */
public class OcspInitializationException extends RuntimeException {

    private static final long serialVersionUID = -7920696456058508107L;

    public OcspInitializationException() {
        super();
    }

    public OcspInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public OcspInitializationException(String message) {
        super(message);
    }

    public OcspInitializationException(Throwable cause) {
        super(cause);
    }

}
