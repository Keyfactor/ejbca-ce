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
package org.ejbca.ui.web.rest.api.types;

import java.math.BigInteger;

/**
 * A class representing general information about certificate. Is used for REST services' responses.
 * 
 * @version $Id: CertificateResponse.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class CertificateResponse {

    private byte[] certificate;
    private BigInteger serialNumber;

    private CertificateResponse(byte[] certificate, BigInteger serialNumber) {
        this.certificate = certificate;
        this.serialNumber = serialNumber;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CertificateResponseBuilder builder() {
        return new CertificateResponseBuilder();
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public static class CertificateResponseBuilder {
        private byte[] certificate;
        private BigInteger serialNumber;

        private CertificateResponseBuilder() {
        }

        public CertificateResponseBuilder setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }

        public CertificateResponseBuilder setSerialNumber(BigInteger serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateResponse build() {
            return new CertificateResponse(certificate, serialNumber);
        }
    }
}
