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
    public static CertificateTypeBuilder builder() {
        return new CertificateTypeBuilder();
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }



    public static class CertificateTypeBuilder {
        private byte[] certificate;
        private BigInteger serialNumber;

        private CertificateTypeBuilder() {
        }

        public CertificateTypeBuilder setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }

        public CertificateTypeBuilder setSerialNumber(BigInteger serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateResponse build() {
            return new CertificateResponse(certificate, serialNumber);
        }
    }
}
