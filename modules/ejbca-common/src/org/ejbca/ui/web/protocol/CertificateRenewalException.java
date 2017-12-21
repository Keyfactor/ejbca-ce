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
package org.ejbca.ui.web.protocol;

/**
 * Thrown if an error occurs during Certificate Renewal.
 * 
 * @version $Id$
 *
 */
public class CertificateRenewalException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * @see java.lang.Exception#Exception()
     */
    public CertificateRenewalException() {
    }

    /**
     * @see java.lang.Exception#Exception(String)
     */
    public CertificateRenewalException(String message) {
        super(message);
    }

    /**
     * @see java.lang.Exception#Exception(Throwable)
     */
    public CertificateRenewalException(Throwable cause) {
        super(cause);
    }

    /**
     * @see java.lang.Exception#Exception(String, Throwable)
     */
    public CertificateRenewalException(String message, Throwable cause) {
        super(message, cause);
    }

}
