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
package org.cesecore.certificates.certificate;

import java.security.cert.Certificate;

/**
 * 
 * Wrapper class for returning cloned specific CertificateData and Base64CertData objects. 
 * 
 * @version $Id$
 *
 */
public class CertificateDataWrapper {

    private final CertificateData certificateData;
    private final Base64CertData base64CertData;
    private final Certificate certificate;

    public CertificateDataWrapper(final Certificate certificate, final CertificateData certificateData, final Base64CertData base64CertData) {
        this.certificate = certificate;
        if (certificateData != null) {
            this.certificateData = new CertificateData(certificateData);
        } else {
            this.certificateData = null;
        }
        if (base64CertData != null) {
            this.base64CertData = new Base64CertData(base64CertData);
        } else {
            this.base64CertData = null;
        }
    }

    public CertificateData getCertificateData() {
        return certificateData;
    }

    public Base64CertData getBase64CertData() {
        return base64CertData;
    }

    public Certificate getCertificate() {
        return certificate;
    }

}
