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
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.ui.web.rest.api.io.request.Pagination;
import org.ejbca.ui.web.rest.api.io.request.PaginationSummary;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;

/**
 * JSON output for certificate search V2.
 */
public class SearchCertificatesRestResponseV2 {

    private static final Logger log = Logger.getLogger(SearchCertificatesRestResponseV2.class);
    
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

        public SearchCertificatesRestResponseV2 toRestResponse(
                final RaCertificateSearchResponseV2 raCertificateSearchResponse, final Pagination pagination,
                final Map<Integer, String> availableEndEntityProfiles,
                final Map<Integer, String> availableCertificateProfiles) throws CertificateEncodingException, CertificateParsingException {
            final SearchCertificatesRestResponseV2 result = new SearchCertificatesRestResponseV2();
            final int count = raCertificateSearchResponse.getCdws().size();
            
            final PaginationSummary summary;
            if (pagination != null) {
                final int pageSize = pagination.getPageSize();
                final int currentPage = pagination.getCurrentPage();
                summary = new PaginationSummary(pageSize, currentPage);
                if (currentPage == -1) {
                    summary.setTotalCerts(raCertificateSearchResponse.getTotalCount());
                } else if (count > 0) {
                    summary.setTotalCerts((long) pageSize * (currentPage - 1) + count);
                }
            } else {
                summary = new PaginationSummary(raCertificateSearchResponse.getTotalCount());
            }
            result.setPaginationSummary(summary);
            for(final CertificateDataWrapper cdw : raCertificateSearchResponse.getCdws()) {
                Certificate certificate = cdw.getCertificate();
                final CertificateData cd = cdw.getCertificateData();
                final Base64CertData base64CertData = cdw.getBase64CertData();

                if (certificate == null && base64CertData != null && base64CertData.getBase64Cert() != null) {
                    try {
                        certificate = CertTools.getCertfromByteArray(Base64.decode(base64CertData.getBase64Cert().getBytes()), Certificate.class);
                    } catch (CertificateParsingException e) {
                        // Should not happen.
                        log.warn("Failed to parse certificate stored in the Base64CertData with issuer '" + cd.getIssuerDN() + "' and SN '" + cd.getSerialNumberHex() + "'.");
                        throw e;
                    }
                }
                
                if (certificate != null && cd != null) {
                    byte[] certificateBytes = certificate.getEncoded();
                    byte[] encodedCertificateBytes = certificateBytes;
                    if (!certificate.getType().equals(SshCertificate.CERTIFICATE_TYPE)) {
                        encodedCertificateBytes = Base64.encode(certificateBytes);
                    }
                    final byte[] skidBytes = CertTools.getSubjectKeyId(certificate);
                    String skid = "";
                    if (skidBytes != null && skidBytes.length > 0) {
                        skid = new String(Hex.encode(skidBytes));
                    }
                    final CertificateRestResponseV2 response = CertificateRestResponseV2.builder()
                        .setFingerprint(CertTools.getFingerprintAsString(certificateBytes))
                        .setCAFingerprint(cd.getCaFingerprint())
                        .setCertificateProfileId(cd.getCertificateProfileId())
                        .setCertificateProfile(availableCertificateProfiles.get(cd.getCertificateProfileId()))
                        .setEndEntityProfileId(cd.getEndEntityProfileId())
                        .setEndEntityProfile(availableEndEntityProfiles.get(cd.getEndEntityProfileId()))
                        .setExpireDate(cd.getExpireDate())
                        .setIssuerDN(cd.getIssuerDN())
                        .setNotBefore(cd.getNotBefore())
                        .setRevocationDate(cd.getRevocationDate())
                        .setRevocationReason(cd.getRevocationReason())
                        .setSerialNumber(CertTools.getSerialNumberAsString(certificate))
                        .setStatus(cd.getStatus())
                        .setSubjectAltName(cd.getSubjectAltName())
                        .setSubjectDN(cd.getSubjectDN())
                        .setSubjectKeyId(skid)
                        .setTag(cd.getTag())
                        .setType(cd.getType())
                        .setUpdateTime(cd.getUpdateTime())
                        .setUsername(cd.getUsername())
                        .setCertificate(encodedCertificateBytes)
                        .setCertificateRequest(cd.getCertificateRequest())
                        .build();
                    result.getCertificates().add(response);
                }
            }
            return result;
        }
    }
}
