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

import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.ui.web.rest.api.io.request.Pagination;
import org.ejbca.ui.web.rest.api.io.request.PaginationSummary;

/**
 * JSON output for certificate search V2.
 */
public class SearchCertificatesRestResponseV2 {

    private List<CertificateRestResponseV2> certificates = new ArrayList<>();
    
    private PaginationSummary paginationSummary;

    public SearchCertificatesRestResponseV2(){
    }

    public List<CertificateRestResponseV2> getCertificates() {
        return certificates;
    }

    public void setCertificates(final List<CertificateRestResponseV2> certificates) {
        this.certificates = certificates;
    }

    public PaginationSummary getPaginationSummary() {
        return paginationSummary;
    }

    public void setPaginationSummary(PaginationSummary paginationSummary) {
        this.paginationSummary = paginationSummary;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchCertificatesRestResponseBuilderV2 builder() {
        return new SearchCertificatesRestResponseBuilderV2();
    }

    public static class SearchCertificatesRestResponseBuilderV2 {
        
        private List<CertificateRestResponseV2> certificates;

        private PaginationSummary paginationSummary;
        
        private SearchCertificatesRestResponseBuilderV2() {
        }

        public SearchCertificatesRestResponseBuilderV2 certificates(final List<CertificateRestResponseV2> certificates) {
            this.certificates = certificates;
            return this;
        }
        
        public SearchCertificatesRestResponseBuilderV2 moreResults(final PaginationSummary paginationSummary) {
            this.paginationSummary = paginationSummary;
            return this;
        }

        public SearchCertificatesRestResponseV2 build() {
            final SearchCertificatesRestResponseV2 result = new SearchCertificatesRestResponseV2();
            result.setCertificates(certificates);
            result.setPaginationSummary(paginationSummary);
            return result;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchCertificatesRestResponseConverterV2 converter() {
        return new SearchCertificatesRestResponseConverterV2();
    }

    public static class SearchCertificatesRestResponseConverterV2 {

        public SearchCertificatesRestResponseV2 toRestResponse(final RaCertificateSearchResponseV2 raCertificateSearchResponse, final Pagination pagination) throws CertificateEncodingException {
            final SearchCertificatesRestResponseV2 result = new SearchCertificatesRestResponseV2();
            final PaginationSummary summary;
            if (pagination != null) {
                summary = new PaginationSummary(pagination.getPageSize(), pagination.getCurrentPage());
            } else {
                summary = new PaginationSummary(raCertificateSearchResponse.getTotalCount());
            }
            result.setPaginationSummary(summary);
            for(final CertificateDataWrapper cdw : raCertificateSearchResponse.getCdws()) {
                final Certificate certificate = cdw.getCertificate();
                final CertificateData cd = cdw.getCertificateData();
                // We have to check for null as we can issue certificates without storing the certificate data in the database
                if (certificate != null && cd != null) {
                    final byte[] certificateBytes = certificate.getEncoded();
                    final CertificateRestResponseV2 response = CertificateRestResponseV2.builder()
                        .setFingerprint(CertTools.getFingerprintAsString(certificateBytes))
                        .setCAFingerprint(cd.getCaFingerprint())
                        .setCertificateProfileId(cd.getCertificateProfileId())
                        .setEndEntityProfileId(cd.getEndEntityProfileId())
                        .setExpireDate(cd.getExpireDate())
                        .setIssuerDN(cd.getIssuerDN())
                        .setNotBefore(cd.getNotBefore())
                        .setRevocationDate(cd.getRevocationDate())
                        .setRevocationReason(cd.getRevocationReason())
                        .setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                        .setStatus(cd.getStatus())
                        .setSubjectAltName(cd.getSubjectAltName())
                        .setSubjectDN(cd.getSubjectDN())
                        .setSubjectKeyId(new String(CertTools.getSubjectKeyId(certificate), StandardCharsets.UTF_8))
                        .setTag(cd.getTag())
                        .setType(cd.getType())
                        .setUpdateTime(cd.getUpdateTime())
                        .setUsername(cd.getUsername())
                        .setCertificate(Base64.encode(certificateBytes))
                        .setCertificateRequest(cd.getCertificateRequest())
                        .build();
                    result.getCertificates().add(response);
                }
            }
            return result;
        }
    }
}
