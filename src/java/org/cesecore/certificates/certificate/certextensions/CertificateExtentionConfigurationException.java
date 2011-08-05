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
package org.cesecore.certificates.certificate.certextensions;

/**
 * Exception thrown of advanced certificate extensions when it is configured with bad properties.
 * 
 * 
 * Based on EJBCA version: CertificateExtentionConfigurationException.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id: CertificateExtentionConfigurationException.java 158 2011-01-26 14:48:51Z mikek $
 */
public class CertificateExtentionConfigurationException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Exception thrown of advanced certificate extensions when it is configured with bad properties.
     */
    public CertificateExtentionConfigurationException(String message, Throwable throwable) {
        super(message, throwable);
    }

    /**
     * Exception thrown of advanced certificate extensions when it is configured with bad properties.
     */
    public CertificateExtentionConfigurationException(String message) {
        super(message);
    }
}
