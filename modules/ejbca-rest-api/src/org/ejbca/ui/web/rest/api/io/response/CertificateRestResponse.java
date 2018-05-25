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
package org.ejbca.ui.web.rest.api.io.response;

import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * A class representing general information about certificate. Is used for REST services' responses.
 *
 * @version $Id: CertificateRestResponse.java 28909 2018-05-10 12:16:53Z tarmo_r_helmes $
 */
public class CertificateRestResponse {

    private byte[] certificate;
    private BigInteger serialNumber;

    private CertificateRestResponse(byte[] certificate, BigInteger serialNumber) {
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

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static CertificateRestResponseConverter converter() {
        return new CertificateRestResponseConverter();
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

        public CertificateRestResponse build() {
            return new CertificateRestResponse(certificate, serialNumber);
        }
    }

    public static class CertificateRestResponseConverter {

        public CertificateRestResponse toRestResponse(Certificate certificate) throws CertificateEncodingException {
            certificate.getType();
            return CertificateRestResponse.builder()
                    .setCertificate(Base64.encode(certificate.getEncoded()))
                    .setSerialNumber(CertTools.getSerialNumber(certificate))
                    .build();
        }

        public CertificateRestResponse toRestResponse(X509Certificate certificate) throws CertificateEncodingException {
            certificate.getType();
            return CertificateRestResponse.builder()
                    .setCertificate(certificate.getEncoded())
                    .setSerialNumber(certificate.getSerialNumber())
                    .build();
        }

    }
}
