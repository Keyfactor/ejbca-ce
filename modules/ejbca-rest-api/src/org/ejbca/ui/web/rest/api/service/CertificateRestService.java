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
package org.ejbca.ui.web.rest.api.service;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;

import javax.ws.rs.core.Response;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;

/**
 * Service layer to support the certificate REST resource operations.
 *
 * @version $Id: CertificateRestService.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class CertificateRestService extends RestService {

    public CertificateRestService() {
        super();
    }

    /**
     * Authorizes the input search request for proper access references (End entity profile ids, Certificate profile ids and CA ids) inside a request.
     *
     * @param authenticationToken authentication token to use.
     * @param searchCertificatesRestRequest input search request.
     * @throws RestException In case of inaccessible reference usage.
     */
    public void authorizeSearchCertificatesRestRequestReferences(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws RestException {
        Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
        Map<Integer, String> availableCertificateProfiles = new HashMap<>();
        Map<Integer, String> availableCAs = new HashMap<>();
        for(SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : searchCertificatesRestRequest.getCriteria()) {
            final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
            if(criteriaProperty == null) {
                throw new RestException(
                        Response.Status.BAD_REQUEST.getStatusCode(),
                        "Invalid search criteria content."
                );
            }
            switch (criteriaProperty) {
                case END_ENTITY_PROFILE:
                    availableEndEntityProfiles = loadAuthorizedEndEntityProfiles(authenticationToken, availableEndEntityProfiles);
                    final String criteriaEndEntityProfileName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaEndEntityProfileId = getKeyFromMapByValue(availableEndEntityProfiles, criteriaEndEntityProfileName);
                    if(criteriaEndEntityProfileId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown end entity profile."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaEndEntityProfileId);
                    break;
                case CERTIFICATE_PROFILE:
                    availableCertificateProfiles = loadAuthorizedCertificateProfiles(authenticationToken, availableCertificateProfiles);
                    final String criteriaCertificateProfileName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaCertificateProfileId = getKeyFromMapByValue(availableCertificateProfiles, criteriaCertificateProfileName);
                    if(criteriaCertificateProfileId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown certificate profile."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaCertificateProfileId);
                    break;
                case CA:
                    availableCAs = loadAuthorizedCAs(authenticationToken, availableCAs);
                    final String criteriaCAName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaCAId = getKeyFromMapByValue(availableCAs, criteriaCAName);
                    if(criteriaCAId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown CA."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaCAId);
                    break;
                default:
                    // Do nothing
            }
        }
    }

    /**
     * Searches for certificates within given criteria.
     *
     * @param authenticationToken authentication token to use.
     * @param searchCertificatesRestRequest search criteria.
     * @return Search results.
     * @throws RestException In case of malformed criteria.
     * @throws CertificateEncodingException In case of failure in certificate reading.
     */
    public SearchCertificatesRestResponse searchCertificates(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws RestException, CertificateEncodingException {
        final RaCertificateSearchRequest raCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        final RaCertificateSearchResponse raCertificateSearchResponse = raMasterApi.searchForCertificates(authenticationToken, raCertificateSearchRequest);
        return SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse);
    }

    private Map<Integer, String> loadAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableEndEntityProfiles) {
        if(availableEndEntityProfiles.isEmpty()) {
            return super.getAuthorizedEndEntityProfiles(authenticationToken);
        }
        return availableEndEntityProfiles;
    }

    private Map<Integer, String> loadAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableCertificateProfiles) {
        if(availableCertificateProfiles.isEmpty()) {
            return super.getAuthorizedCertificateProfiles(authenticationToken);
        }
        return availableCertificateProfiles;
    }

    private Map<Integer, String> loadAuthorizedCAs(final AuthenticationToken authenticationToken, final Map<Integer, String> availableCAs) {
        if(availableCAs.isEmpty()) {
            return super.getAuthorizedCAs(authenticationToken);
        }
        return availableCAs;
    }

    private Integer getKeyFromMapByValue(final Map<Integer, String> map, final String value) {
        for(Integer key : map.keySet()) {
            if(map.get(key).equals(value)) {
                return key;
            }
        }
        return null;
    }
}
