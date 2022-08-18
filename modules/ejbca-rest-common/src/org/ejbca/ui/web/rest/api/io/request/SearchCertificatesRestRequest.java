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
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequestList;
import org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateMaxNumberOfResults;

import javax.validation.Valid;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

import static org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestUtil.parseDateFromStringValue;

/**
 * JSON input for a certificate search containing multiple search criteria and output limitation.
 * <br/>
 * The properties of this class has to be valid.
 *
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequestList
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateCriteriaRestRequest
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchCertificateMaxNumberOfResults
 *
 * @version $Id: SearchCertificatesRestRequest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class SearchCertificatesRestRequest implements SearchCertificateCriteriaRequest {

    @ApiModelProperty(value = "Maximum number of results", example = "10")
    @ValidSearchCertificateMaxNumberOfResults
    private Integer maxNumberOfResults;
    @ApiModelProperty(value = "A List of search criteria." )
    @ValidSearchCertificateCriteriaRestRequestList
    @Valid
    private List<SearchCertificateCriteriaRestRequest> criteria = new ArrayList<>();

    public Integer getMaxNumberOfResults() {
        return maxNumberOfResults;
    }

    public void setMaxNumberOfResults(Integer maxNumberOfResults) {
        this.maxNumberOfResults = maxNumberOfResults;
    }

    @Override
    public List<SearchCertificateCriteriaRestRequest> getCriteria() {
        return criteria;
    }

    public void setCriteria(List<SearchCertificateCriteriaRestRequest> criteria) {
        this.criteria = criteria;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchCertificatesRestRequestBuilder builder() {
        return new SearchCertificatesRestRequestBuilder();
    }

    public static class SearchCertificatesRestRequestBuilder {
        private Integer maxNumberOfResults;
        private List<SearchCertificateCriteriaRestRequest> criteria;

        private SearchCertificatesRestRequestBuilder() {
        }

        public SearchCertificatesRestRequestBuilder maxNumberOfResults(final Integer maxNumberOfResults) {
            this.maxNumberOfResults = maxNumberOfResults;
            return this;
        }

        public SearchCertificatesRestRequestBuilder criteria(final List<SearchCertificateCriteriaRestRequest> criteria) {
            this.criteria = criteria;
            return this;
        }

        public SearchCertificatesRestRequest build() {
            final SearchCertificatesRestRequest searchCertificatesRestRequest = new SearchCertificatesRestRequest();
            searchCertificatesRestRequest.setMaxNumberOfResults(maxNumberOfResults);
            searchCertificatesRestRequest.setCriteria(criteria);
            return searchCertificatesRestRequest;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchCertificatesRestRequestConverter converter() {
        return new SearchCertificatesRestRequestConverter();
    }

    public static class SearchCertificatesRestRequestConverter {

        public RaCertificateSearchRequest toEntity(final SearchCertificatesRestRequest searchCertificatesRestRequest) throws RestException {
            if(searchCertificatesRestRequest.getMaxNumberOfResults() == null || searchCertificatesRestRequest.getCriteria() == null || searchCertificatesRestRequest.getCriteria().isEmpty()) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
            }
            final RaCertificateSearchRequest raCertificateSearchRequest = new RaCertificateSearchRequest();
            raCertificateSearchRequest.setMaxResults(searchCertificatesRestRequest.getMaxNumberOfResults());
            raCertificateSearchRequest.setEepIds(new ArrayList<Integer>());
            raCertificateSearchRequest.setCpIds(new ArrayList<Integer>());
            raCertificateSearchRequest.setCaIds(new ArrayList<Integer>());
            raCertificateSearchRequest.setStatuses(new ArrayList<Integer>());
            raCertificateSearchRequest.setRevocationReasons(new ArrayList<Integer>());
            for(final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : searchCertificatesRestRequest.getCriteria()) {
                final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
                if(criteriaProperty == null) {
                    throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                }
                final String criteriaValue = searchCertificateCriteriaRestRequest.getValue();
                final SearchCertificateCriteriaRestRequest.CriteriaOperation criteriaOperation = SearchCertificateCriteriaRestRequest.CriteriaOperation.resolveCriteriaOperation(searchCertificateCriteriaRestRequest.getOperation());
                switch (criteriaProperty) {
                    case QUERY: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raCertificateSearchRequest.setSubjectDnSearchExact(true);
                            raCertificateSearchRequest.setSubjectAnSearchExact(true);
                            raCertificateSearchRequest.setUsernameSearchExact(true);
                            raCertificateSearchRequest.setExternalAccountIdSearchExact(true);
                        }
                        raCertificateSearchRequest.setSubjectDnSearchString(criteriaValue);
                        raCertificateSearchRequest.setSubjectAnSearchString(criteriaValue);
                        raCertificateSearchRequest.setUsernameSearchString(criteriaValue);
                        raCertificateSearchRequest.setSerialNumberSearchStringFromDec(criteriaValue);
                        raCertificateSearchRequest.setSerialNumberSearchStringFromHex(criteriaValue);
                        raCertificateSearchRequest.setExternalAccountIdSearchString(criteriaValue);
                        break;
                    }
                    case END_ENTITY_PROFILE: {
                        raCertificateSearchRequest.getEepIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case EXTERNAL_ACCOUNT_BINDING_ID: {
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raCertificateSearchRequest.setExternalAccountIdSearchExact(true);
                        }
                        raCertificateSearchRequest.setExternalAccountIdSearchString(criteriaValue);
                        break;
                    }
                    case CERTIFICATE_PROFILE: {
                        raCertificateSearchRequest.getCpIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case CA: {
                        raCertificateSearchRequest.getCaIds().add(searchCertificateCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case STATUS: {
                        final SearchCertificateCriteriaRestRequest.CertificateStatus certificateStatus = SearchCertificateCriteriaRestRequest.CertificateStatus.resolveCertificateStatusByName(criteriaValue);
                        if(certificateStatus == null) {
                            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                        }
                        if (certificateStatus == SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_ACTIVE) {
                            raCertificateSearchRequest.getStatuses().add(certificateStatus.getStatusValue());
                            // ECA-8578: when searching for active certificates we need to include certificates that are notified about expiration.
                            // Add this automatically to the search conditions.
                            raCertificateSearchRequest.getStatuses().add(CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
                        }
                        if (certificateStatus == SearchCertificateCriteriaRestRequest.CertificateStatus.CERT_REVOKED) {
                            raCertificateSearchRequest.getStatuses().add(certificateStatus.getStatusValue());
                        }
                        if (SearchCertificateCriteriaRestRequest.CertificateStatus.REVOCATION_REASONS().contains(certificateStatus)) {
                            raCertificateSearchRequest.getRevocationReasons().add(certificateStatus.getStatusValue());
                        }
                        break;
                    }
                    case ISSUED_DATE: {
                        final long issuedDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raCertificateSearchRequest.setIssuedAfter(issuedDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raCertificateSearchRequest.setIssuedBefore(issuedDateLong);
                        }
                        break;
                    }
                    case EXPIRE_DATE: {
                        final long expireDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raCertificateSearchRequest.setExpiresAfter(expireDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raCertificateSearchRequest.setExpiresBefore(expireDateLong);
                        }
                        break;
                    }
                    case REVOCATION_DATE: {
                        final long revocationDateLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raCertificateSearchRequest.setRevokedAfter(revocationDateLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raCertificateSearchRequest.setRevokedBefore(revocationDateLong);
                        }
                        break;
                    }
                    case UPDATE_TIME: {
                        final long updateTimeLong = parseDateFromStringValue(criteriaValue).getTime();
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER) {
                            raCertificateSearchRequest.setUpdatedAfter(updateTimeLong);
                        }
                        if (criteriaOperation == SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE) {
                            raCertificateSearchRequest.setUpdatedBefore(updateTimeLong);
                        }
                        break;
                    }
                }
            }
            return raCertificateSearchRequest;
        }
    }

}
