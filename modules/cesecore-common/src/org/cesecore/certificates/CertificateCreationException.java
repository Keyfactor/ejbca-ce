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
package org.cesecore.certificates;

/**
 * RuntimeException thrown when an error is encountered during certificate creation.
 * 
 * @version $Id$
 *
 */
public class CertificateCreationException extends RuntimeException {

    private static final long serialVersionUID = -3148367537076684178L;

    public CertificateCreationException() {
    }
    
    public CertificateCreationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateCreationException(String message) {
        super(message);
    }

    public CertificateCreationException(Throwable cause) {
        super(cause);
    }

}
