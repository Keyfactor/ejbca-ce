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

import org.ejbca.core.model.era.RaEndEntityProfileResponse;

import java.util.List;

/**
 * JSON output for end entity profile.
 */
public class EndEntityProfileResponse {

    private String endEntityProfileName;
    private List<String> availableCAs;
    private List<String> availableCertificateProfiles;
    private List<String> subjectDomainNameFields;
    private List<String> subjectAltNameFields;

    public EndEntityProfileResponse() {
    }

    public EndEntityProfileResponse(String eepName, List<String> availableCAs, List<String> availableCertificateProfiles, List<String> sDNFields, List<String> sANFields) {
        this.endEntityProfileName = eepName;
        this.availableCAs = availableCAs;
        this.availableCertificateProfiles = availableCertificateProfiles;
        this.subjectDomainNameFields = sDNFields;
        this.subjectAltNameFields = sANFields;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public List<String> getAvailableCAs() {
        return availableCAs;
    }

    public List<String> getAvailableCertificateProfiles() {
        return availableCertificateProfiles;
    }

    public List<String> getSubjectDomainNameFields() {
        return subjectDomainNameFields;
    }

    public List<String> getSubjectAltNameFields() {
        return subjectAltNameFields;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static EndEntityProfileResponseConverter converter() {
        return new EndEntityProfileResponseConverter();
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static EndEntityProfileResponseBuilder builder() {
        return new EndEntityProfileResponseBuilder();
    }

    /**
     * Builder of this class.
     */
    public static class EndEntityProfileResponseBuilder {
        private String eepName;
        private List<String> availableCAs;
        private List<String> availableCertificateProfiles;
        private List<String> sDNFields;
        private List<String> sANFields;

        public EndEntityProfileResponseBuilder() {
        }

        public EndEntityProfileResponseBuilder eepName(String eepName) {
            this.eepName = eepName;
            return this;
        }

        public EndEntityProfileResponseBuilder availableCAs(List<String> availableCAs) {
            this.availableCAs = availableCAs;
            return this;
        }

        public EndEntityProfileResponseBuilder sDNFields(List<String> sDNFields) {
            this.sDNFields = sDNFields;
            return this;
        }

        public EndEntityProfileResponseBuilder sANFields(List<String> sANFields) {
            this.sANFields = sANFields;
            return this;
        }

        public EndEntityProfileResponseBuilder availableCertificateProfiles(List<String> availableCertificateProfiles) {
            this.availableCertificateProfiles = availableCertificateProfiles;
            return this;
        }
        public EndEntityProfileResponse build() {
            return new EndEntityProfileResponse(
                    eepName,
                    availableCAs,
                    availableCertificateProfiles,
                    sDNFields,
                    sANFields
            );
        }
    }

    /**
     * Converter of this class.
     */
    public static class EndEntityProfileResponseConverter {
        public EndEntityProfileResponseConverter() {
        }

        /**
         * Converts a non-null instance of RaEndEntityProfileResponse into EndEntityProfileResponse.
         *
         * @param raEndEntityProfileResponse RaEndEntityProfileResponse.
         *
         * @return EndEntityProfileResponse.
         */
        public EndEntityProfileResponse toRestResponse(final RaEndEntityProfileResponse raEndEntityProfileResponse)  {
            return EndEntityProfileResponse.builder()
                    .eepName(raEndEntityProfileResponse.getEepName())
                    .availableCAs(raEndEntityProfileResponse.getAvailableCAs())
                    .availableCertificateProfiles(raEndEntityProfileResponse.getAvailableCertificateProfiles())
                    .sDNFields(raEndEntityProfileResponse.getSubdjectDNFields())
                    .sANFields(raEndEntityProfileResponse.getSubjectANFields())
                    .build();
        }
    }
}
