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

import com.fasterxml.jackson.annotation.JsonInclude;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A class representing general information about certificate. Is used for REST services' responses.
 *
 * @version $Id: CertificateRestResponse.java 29010 2018-05-23 13:09:53Z andrey_s_helmes $
 */
public class CertificateRestResponse {

    private byte[] certificate;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private BigInteger serialNumber;
    private String responseFormat;

    private CertificateRestResponse(byte[] certificate, BigInteger serialNumber, String responseFormat) {
        this.certificate = certificate;
        this.serialNumber = serialNumber;
        this.responseFormat = responseFormat;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CertificateRestResponseBuilder builder() {
        return new CertificateRestResponseBuilder();
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
        // JSON serialization --> Base64 String. Don't do it manually
        return certificate;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public String getResponseFormat() {
        return responseFormat;
    }
    
    public static class CertificateRestResponseBuilder {
        private byte[] certificate;
        private BigInteger serialNumber;
        private String responseFormat;
        
        private CertificateRestResponseBuilder() {
        }

        public CertificateRestResponseBuilder setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }

        public CertificateRestResponseBuilder setSerialNumber(BigInteger serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateRestResponseBuilder setResponseFormat(String responseFormat) {
            this.responseFormat = responseFormat;
            return this;
        }
        
        public CertificateRestResponse build() {
            return new CertificateRestResponse(certificate, serialNumber, responseFormat);
        }
    }

    public static class CertificateRestResponseConverter {

        public CertificateRestResponse toRestResponse (Certificate certificate) throws CertificateEncodingException {
            certificate.getType();
            return CertificateRestResponse.builder()
                    .setCertificate(Base64.encode(certificate.getEncoded()))
                    .setSerialNumber(CertTools.getSerialNumber(certificate))
                    .setResponseFormat("DER")
                    .build();
        }

        public CertificateRestResponse toRestResponse (X509Certificate certificate) throws CertificateEncodingException {
            certificate.getType();
            return CertificateRestResponse.builder()
                    .setCertificate(certificate.getEncoded())
                    .setSerialNumber(certificate.getSerialNumber())
                    .setResponseFormat("DER")
                    .build();
        }
        
        public CertificateRestResponse toRestResponse (KeyStore keyStore, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
            return CertificateRestResponse.builder()
                    .setCertificate(lockKeyStore(keyStore, password))
                    .setResponseFormat(keyStore.getType())
                    .build();
        }
    }
    
    private static byte[] lockKeyStore(KeyStore keyStore, String password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        return baos.toByteArray();
    }
}
