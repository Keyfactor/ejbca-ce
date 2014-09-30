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
package org.ejbca.ui.web;

import java.security.cert.Certificate;

/**
 * Holds a return value with a certificate in both object form and encoded form.
 * 
 * @version $Id$
 */
public class CertificateRequestResponse {

    private final Certificate certificate;
    private final byte[] encoded;
    
    /** Object is created internally only */
    CertificateRequestResponse(Certificate certificate, byte[] encoded) {
        this.certificate = certificate;
        this.encoded = encoded;
    }
    
    /** Returns the signed certificate. */
    public Certificate getCertificate() { return certificate; }
    /** Returns the encoded form of the certificate. Might be a certificate or chain in PEM or DER format, or a PKCS7 in PEM format */
    public byte[] getEncoded() { return encoded; }

}
