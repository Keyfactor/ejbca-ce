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

import java.util.List;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.ejbca.core.model.era.RaCertificateProfileResponseV2;

/**
 * Output for certificate profile info V2.
 */
public class CertificateProfileInfoRestResponseV2 {

    private Integer certificateProfileId;
    private List<String> availableKeyAlgs;

    @Schema(description = "Alternative algorithm keys")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonAlias({"availableAltKeyAlgs", "available_alt_key_algs" })
    private List<String> availableAltKeyAlgs;

    private List<Integer> availableBitLenghts;
    private List<String> availableEcdsaCurves;
    private List<String> availableCas;
    
    private List<Integer> keyUsages;
    private List<String> extendedKeyUsages;
    private String validity;
    
    public CertificateProfileInfoRestResponseV2(List<String> availableKeyAlgs, List<String> availableAltKeyAlgs, List<Integer> availableBitLengths,
            List<String> availableEcdsaCurves, List<String> availableCas, final Integer certificateProfileId, final List<Integer> keyUsages, 
            final List<String> extendedKeyUsages, final String validity) {
        this.certificateProfileId = certificateProfileId;
        this.availableKeyAlgs = availableKeyAlgs;
        this.availableAltKeyAlgs = availableAltKeyAlgs;
        this.availableBitLenghts = availableBitLengths;
        this.availableEcdsaCurves = availableEcdsaCurves;
        this.availableCas = availableCas;
        this.keyUsages = keyUsages;
        this.extendedKeyUsages = extendedKeyUsages;
        this.validity = validity;
    }
    
    public CertificateProfileInfoRestResponseV2() {
        
    }

    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }

    public List<String> getAvailableKeyAlgs() {
        return availableKeyAlgs;
    }

    public List<String> getAvailableAltKeyAlgs() {
        return availableAltKeyAlgs;
    }
    
    public List<Integer> getAvailableBitLenghts() {
        return availableBitLenghts;
    }
    
    public List<String> getAvailableEcdsaCurves() {
        return availableEcdsaCurves;
    }

    public List<String> getAvailableCas() {
        return availableCas;
    }
    
    public List<Integer> getKeyUsages() {
        return keyUsages;
    }
    
    public List<String> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }
    
    public String getValidity() {
        return validity;
    }

    /**
     * Returns a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CertificateProfileInfoRestResponseBuilderV2 builder() {
        return new CertificateProfileInfoRestResponseBuilderV2();
    }

    public static class CertificateProfileInfoRestResponseBuilderV2 {
        private Integer certificateProfileId;
        private List<String> availableProfileAlgorithms;
        private List<String> availableProfileAlternativeAlgorithms;
        private List<Integer> availableProfileBitLengths;
        private List<String> availableProfileEcdsaCurves;
        private List<String> availableProfileCas;
        private List<Integer> keyUsages;
        private List<String> extendedKeyUsages;
        private String validity;
        
        public CertificateProfileInfoRestResponseBuilderV2() {}

        public CertificateProfileInfoRestResponseBuilderV2 setCertificateProfileId(final Integer certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableProfileAlgorithms(List<String> availableProfileAlgorithms) {
            this.availableProfileAlgorithms = availableProfileAlgorithms;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableProfileAlternativeAlgorithms(List<String> availableProfileAlternativeAlgorithms) {
            this.availableProfileAlternativeAlgorithms = availableProfileAlternativeAlgorithms;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableBitLengths(List<Integer> availableProfileBitLengths) {
            this.availableProfileBitLengths = availableProfileBitLengths;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableEcdsaCurves(List<String> availableProfileEcdsaCurves ) {
            this.availableProfileEcdsaCurves = availableProfileEcdsaCurves;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableProfileCAs(List<String> availableProfileCas) {
            this.availableProfileCas = availableProfileCas;
            return this;
        }
        
        public CertificateProfileInfoRestResponseBuilderV2 setKeyUsages(List<Integer> keyUsages) {
            this.keyUsages = keyUsages;
            return this;
        }
        
        public CertificateProfileInfoRestResponseBuilderV2 setExtendedKeyUsages(List<String> extendedKeyUsages) {
            this.extendedKeyUsages = extendedKeyUsages;
            return this;
        }
        
        public CertificateProfileInfoRestResponseBuilderV2 setValidity(String validity) {
            this.validity = validity;
            return this;
        }

        public CertificateProfileInfoRestResponseV2 build() {
            return new CertificateProfileInfoRestResponseV2(availableProfileAlgorithms, availableProfileAlternativeAlgorithms, availableProfileBitLengths,
                                                            availableProfileEcdsaCurves, availableProfileCas, certificateProfileId, keyUsages, extendedKeyUsages, validity);
        }
    }
    
    public CertificateProfileInfoRestResponseConverterV2 convert() {
        return new CertificateProfileInfoRestResponseConverterV2();
    }
    
    public static class CertificateProfileInfoRestResponseConverterV2 {
        public CertificateProfileInfoRestResponseConverterV2() {};
        
        public CertificateProfileInfoRestResponseV2 toCertificateProfileInfoRestResponse(RaCertificateProfileResponseV2 raResponse) {
            return CertificateProfileInfoRestResponseV2.builder().setCertificateProfileId(raResponse.getCertificateProfileId())
                    .setAvailableProfileAlgorithms(raResponse.getAvailableAlgorithms())
                    .setAvailableProfileAlternativeAlgorithms(raResponse.getAvailableAlternativeAlgorithms())
                    .setAvailableBitLengths(raResponse.getAvailableBitLengths())
                    .setAvailableEcdsaCurves(raResponse.getAvailableEcdsaCurves())
                    .setAvailableProfileCAs(raResponse.getAvailableCas())
                    .setKeyUsages(raResponse.getKeyUsages())
                    .setExtendedKeyUsages(raResponse.getExtendedKeyUsages())
                    .setValidity(raResponse.getValidity())
                    .build();
        }
    }
}