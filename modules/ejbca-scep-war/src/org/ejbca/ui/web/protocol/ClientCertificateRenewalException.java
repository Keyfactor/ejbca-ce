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
 * Thrown if an error occurs during Client Certificate Renewal.
 * 
 * @version $Id$
 *
 */
public class ClientCertificateRenewalException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public ClientCertificateRenewalException() {
    }

    /**
     * @param message
     */
    public ClientCertificateRenewalException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public ClientCertificateRenewalException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public ClientCertificateRenewalException(String message, Throwable cause) {
        super(message, cause);
    }

}
