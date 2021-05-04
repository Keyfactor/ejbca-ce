/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.SecConst;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A class representing general information about certificate. Is used for REST services' responses.
 */
public class CertificateRestResponse {
    private byte[] certificate;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String serialNumber;
    private String responseFormat;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<byte[]> certificateChain;

    private CertificateRestResponse(final CertificateRestResponseBuilder builder) {
        this.certificate = builder.certificate;
        this.serialNumber = builder.serialNumber;
        this.responseFormat = builder.responseFormat;
        this.certificateChain = builder.certificateChain;
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

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    public List<byte[]> getCertificateChain() { return certificateChain; }
    
    public static class CertificateRestResponseBuilder {
        private byte[] certificate;
        private String serialNumber;
        private String responseFormat;
        private List<byte[]> certificateChain;
        
        private CertificateRestResponseBuilder() {
        }

        public CertificateRestResponseBuilder setCertificate(byte[] certificate) {
            this.certificate = certificate;
            return this;
        }

        public CertificateRestResponseBuilder setSerialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public CertificateRestResponseBuilder setResponseFormat(String responseFormat) {
            this.responseFormat = responseFormat;
            return this;
        }

        public CertificateRestResponseBuilder setResponseFormat(int keystoreType) {
            this.responseFormat =
                    keystoreType == SecConst.TOKEN_SOFT_JKS ? "JKS" :
                    keystoreType == SecConst.TOKEN_SOFT_PEM ? "PEM" :
                    keystoreType == SecConst.TOKEN_SOFT_P12 ? "PKCS12" :
                    keystoreType == SecConst.TOKEN_SOFT_BCFKS ? "BCFKS" :
                            "UNKNOWN";
            return this;
        }

        public CertificateRestResponseBuilder setCertificateChain(final List<byte[]> certificateChain) {
            this.certificateChain = certificateChain;
            return this;
        }
        
        public CertificateRestResponse build() {
            return new CertificateRestResponse(this);
        }
    }

    public static class CertificateRestResponseConverter {
        public CertificateRestResponse toRestResponse(final Certificate certificate) {
            return CertificateRestResponse.builder()
                    .setCertificate(getEncodedCertificate(certificate))
                    .setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                    .setResponseFormat("DER")
                    .build();
        }

        public CertificateRestResponse toRestResponse(final List<Certificate> certificateChain, final Certificate certificate) {
            return CertificateRestResponse.builder()
                    .setCertificate(getEncodedCertificate(certificate))
                    .setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                    .setCertificateChain(certificateChain == null ? null : certificateChain
                            .stream()
                            .map(c -> getEncodedCertificate(c))
                            .collect(Collectors.toList()))
                    .setResponseFormat("DER")
                    .build();
        }
        
        public CertificateRestResponse toRestResponse(final byte[] keyStoreBytes, final int keystoreType)  {
            return CertificateRestResponse.builder()
                    .setCertificate(keyStoreBytes)
                    .setResponseFormat(keystoreType)
                    .build();
        }

        private byte[] getEncodedCertificate(final Certificate certificate) {
            try {
                return certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
