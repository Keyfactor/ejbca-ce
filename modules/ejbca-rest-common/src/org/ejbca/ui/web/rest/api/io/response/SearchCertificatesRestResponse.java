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

import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.era.RaCertificateSearchResponse;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * JSON output for certificate search.
 *
 * @version $Id: CertificateService.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class SearchCertificatesRestResponse {

    private List<CertificateRestResponse> certificates = new ArrayList<>();
    private boolean moreResults;

    public SearchCertificatesRestResponse(){
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

        public SearchCertificatesRestResponse toRestResponse(final RaCertificateSearchResponse raCertificateSearchResponse) throws CertificateEncodingException {
            final SearchCertificatesRestResponse searchCertificatesRestResponse = new SearchCertificatesRestResponse();
            searchCertificatesRestResponse.setMoreResults(raCertificateSearchResponse.isMightHaveMoreResults());
            for(final CertificateDataWrapper certificateDataWrapper : raCertificateSearchResponse.getCdws()) {
                final Certificate certificate = certificateDataWrapper.getCertificate();
                final CertificateRestResponse certificateRestResponse = CertificateRestResponse.builder()
                        .setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                        .setCertificate(Base64.encode(certificate.getEncoded()))
                        .setResponseFormat("DER")
                        .build();
                searchCertificatesRestResponse.getCertificates().add(certificateRestResponse);
            }
            return searchCertificatesRestResponse;
        }
    }
}
