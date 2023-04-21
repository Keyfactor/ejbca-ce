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
import com.keyfactor.util.CertTools;

import io.swagger.annotations.ApiModelProperty;

import org.ejbca.core.model.SecConst;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A class representing general information about certificate. Is used for REST services' responses.
 */
public class CertificateRestResponse {
    @ApiModelProperty(value = "Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private byte[] certificate;
    @ApiModelProperty(value = "Hex Serial Number", example = "1234567890ABCDEF")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String serialNumber;
    @ApiModelProperty(value = "Response format", example = "DER")
    private String responseFormat;
    @ApiModelProperty(value = "Certificate chain", example = "[\"ABC123efg...345xyz0=\"]")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<byte[]> certificateChain;
    @ApiModelProperty(value = "Certificate profile name", example = "ENDUSER")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String certificateProfile;
    @ApiModelProperty(value = "End Entity profile name", example = "ExampleEEP")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String endEntityProfile;
    
    private CertificateRestResponse(final CertificateRestResponseBuilder builder) {
        this.certificate = builder.certificate;
        this.serialNumber = builder.serialNumber;
        this.responseFormat = builder.responseFormat;
        this.certificateChain = builder.certificateChain;
        this.certificateProfile = builder.certificateProfile;
        this.endEntityProfile = builder.endEntityProfile;
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
    
    public String getCertificateProfile() {
        return certificateProfile;
    }

    public String getEndEntityProfile() {
        return endEntityProfile;
    }
    
    public List<byte[]> getCertificateChain() { return certificateChain; }
    
    public static class CertificateRestResponseBuilder {
        private byte[] certificate;
        private String serialNumber;
        private String responseFormat;
        private List<byte[]> certificateChain;
        private String certificateProfile;
        private String endEntityProfile;

        
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
        
        public CertificateRestResponseBuilder setCertificateProfile(String certificateProfile) {
            this.certificateProfile = certificateProfile;
            return this;
        }
        
        public CertificateRestResponseBuilder setEndEntityProfile(String endEntityProfile) {
            this.endEntityProfile = endEntityProfile;
            return this;
        }

        public CertificateRestResponseBuilder setResponseFormat(int keystoreType) {
            switch (keystoreType) {
            case SecConst.TOKEN_SOFT_JKS:
                this.responseFormat = "JKS";
                break;
            case SecConst.TOKEN_SOFT_PEM:
                this.responseFormat = "PEM";
                break;
            case SecConst.TOKEN_SOFT_P12:
                this.responseFormat = "PKCS12";
                break;
            case SecConst.TOKEN_SOFT_BCFKS:
                this.responseFormat = "BCFKS";
                break;
            default:
                this.responseFormat = "UNKNOWN";
                break;
            }
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
                            .map(CertificateRestResponseConverter::getEncodedCertificate)
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

        private static byte[] getEncodedCertificate(final Certificate certificate) {
            try {
                return certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
