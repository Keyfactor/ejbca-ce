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
package org.cesecore.certificates.ocsp.standalone.exception;

/**
 * Thrown when an error is encountered while starting OCSP.  
 * 
 * @version $Id$
 *
 */
public class StandaloneOcspInitializationException extends RuntimeException {

    private static final long serialVersionUID = -7920696456058508107L;

    public StandaloneOcspInitializationException() {
        super();
    }

    public StandaloneOcspInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

    public StandaloneOcspInitializationException(String message) {
        super(message);
    }

    public StandaloneOcspInitializationException(Throwable cause) {
        super(cause);
    }

}
