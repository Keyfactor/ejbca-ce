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

import org.ejbca.core.model.era.RaCertificateProfileResponseV2;

/**
 * Output for certificate profile info V2.
 */
public class CertificateProfileInfoRestResponseV2 {

    private Integer certificateProfileId;
    private List<String> availableKeyAlgs;    
    private List<Integer> availableBitLenghts;
    private List<String> availableEcdsaCurves;
    private List<String> availableCas;
    
    public CertificateProfileInfoRestResponseV2(List<String> availableKeyAlgs, List<Integer> availableBitLengths,
            List<String> availableEcdsaCurves, List<String> availableCas, final Integer certificateProfileId) {
        this.certificateProfileId = certificateProfileId;
        this.availableKeyAlgs = availableKeyAlgs;
        this.availableBitLenghts = availableBitLengths;
        this.availableEcdsaCurves = availableEcdsaCurves;
        this.availableCas = availableCas;
    }
    
    public CertificateProfileInfoRestResponseV2() {
        
    }

    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }

    public List<String> getAvailableKeyAlgs() {
        return availableKeyAlgs;
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
        private List<String> availableProfileAlgos;
        private List<Integer> availableProfileBitLengths;
        private List<String> availableProfileEcdsaCurves;
        private List<String> availableProfileCas;
        
        public CertificateProfileInfoRestResponseBuilderV2() {}

        public CertificateProfileInfoRestResponseBuilderV2 setCertificateProfileId(final Integer certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
            return this;
        }

        public CertificateProfileInfoRestResponseBuilderV2 setAvailableAlgos(List<String> availableProfileAlgos) {
            this.availableProfileAlgos = availableProfileAlgos;
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

        public CertificateProfileInfoRestResponseV2 build() {
            return new CertificateProfileInfoRestResponseV2(availableProfileAlgos, availableProfileBitLengths, 
                    availableProfileEcdsaCurves, availableProfileCas, certificateProfileId);
        }
    }
    
    public CertificateProfileInfoRestResponseConverterV2 convert() {
        return new CertificateProfileInfoRestResponseConverterV2();
    }
    
    public static class CertificateProfileInfoRestResponseConverterV2 {
        public CertificateProfileInfoRestResponseConverterV2() {};
        
        public CertificateProfileInfoRestResponseV2 toCertificateProfileInfoRestResponse(RaCertificateProfileResponseV2 raResponse) {
            return CertificateProfileInfoRestResponseV2.builder().setCertificateProfileId(raResponse.getCertificateProfileId())
                    .setAvailableAlgos(raResponse.getAvailableAlgorithms())
                    .setAvailableBitLengths(raResponse.getAvailableBitLengths())
                    .setAvailableEcdsaCurves(raResponse.getAvailableEcdsaCurves())
                    .setAvailableProfileCAs(raResponse.getAvailableCas())
                    .build();
        }
    }
}