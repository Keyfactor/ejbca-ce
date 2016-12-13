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
package org.ejbca.core.model;

/**
 * Thrown to show that the signature of an certificate failed to verify somehow. 
 * 
 * @version $Id$
 *
 */
public class CertificateSignatureException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * @param message
     */
    public CertificateSignatureException(String message) {
        super(message);
    }
    
    /**
     * @param cause
     */
    public CertificateSignatureException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public CertificateSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}
