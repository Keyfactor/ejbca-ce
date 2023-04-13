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

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.ejbca.core.model.era.RaCertificateSearchResponse;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * JSON output for certificate search.
 *
 */
public class SearchCertificatesRestResponse {

    private List<CertificateRestResponse> certificates = new ArrayList<>();
    private boolean moreResults;

    public SearchCertificatesRestResponse(){
        //Empty constructor for JSon support
    }

    public List<CertificateRestResponse> getCertificates() {
        return certificates;
    }

    public void setCertificates(final List<CertificateRestResponse> certificates) {
        this.certificates = certificates;
    }

    public boolean isMoreResults() {
        return moreResults;
    }

    public void setMoreResults(final boolean moreResults) {
        this.moreResults = moreResults;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchCertificatesRestResponseBuilder builder() {
        return new SearchCertificatesRestResponseBuilder();
    }

    public static class SearchCertificatesRestResponseBuilder {
        private boolean moreResults;
        private List<CertificateRestResponse> certificates;

        private SearchCertificatesRestResponseBuilder() {
        }

        public SearchCertificatesRestResponseBuilder moreResults(final boolean moreResults) {
            this.moreResults = moreResults;
            return this;
        }

        public SearchCertificatesRestResponseBuilder certificates(final List<CertificateRestResponse> certificates) {
            this.certificates = certificates;
            return this;
        }

        public SearchCertificatesRestResponse build() {
            final SearchCertificatesRestResponse searchCertificatesRestResponse = new SearchCertificatesRestResponse();
            searchCertificatesRestResponse.setMoreResults(moreResults);
            searchCertificatesRestResponse.setCertificates(certificates);
            return searchCertificatesRestResponse;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchCertificatesRestResponseConverter converter() {
        return new SearchCertificatesRestResponseConverter();
    }

    public static class SearchCertificatesRestResponseConverter {

        public SearchCertificatesRestResponse toRestResponse(final RaCertificateSearchResponse raCertificateSearchResponse, 
                final Map<Integer, String> availableEndEntityProfiles,
                final Map<Integer, String> availableCertificateProfiles) throws CertificateEncodingException {
            final SearchCertificatesRestResponse searchCertificatesRestResponse = new SearchCertificatesRestResponse();
            searchCertificatesRestResponse.setMoreResults(raCertificateSearchResponse.isMightHaveMoreResults());
            for(final CertificateDataWrapper certificateDataWrapper : raCertificateSearchResponse.getCdws()) {
                final Certificate certificate = certificateDataWrapper.getCertificate();
                // We have to check for null as we can issue certificates without storing the certificate data in the database
                if (certificate != null) {
                    CertificateRestResponse.CertificateRestResponseBuilder responseBuilder = CertificateRestResponse.builder();
                    if (certificate.getType().equals(SshCertificate.CERTIFICATE_TYPE)) {
                        responseBuilder.setCertificate(certificate.getEncoded()).setResponseFormat("SSH");
                    } else {
                        responseBuilder.setCertificate(Base64.encode(certificate.getEncoded())).setResponseFormat("DER");
                    }
                    final CertificateRestResponse certificateRestResponse = 
                            responseBuilder.setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                            .setCertificateProfile(availableCertificateProfiles.get(certificateDataWrapper.getCertificateData().getCertificateProfileId()))
                            .setEndEntityProfile(availableEndEntityProfiles.get(certificateDataWrapper.getCertificateData().getEndEntityProfileId()))
			    .build();
                    searchCertificatesRestResponse.getCertificates().add(certificateRestResponse);
                }
            }
            return searchCertificatesRestResponse;
        }
    }
}
