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
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * Service layer to support the certificate REST resource operations.
 *
 * @version $Id: CertificateRestService.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class CertificateRestService extends RestService {

    @Inject
    public CertificateRestService(
            final EjbcaRestHelperSessionLocal ejbcaRestHelperSession,
            final RaMasterApiProxyBeanLocal raMasterApi) {
        super(ejbcaRestHelperSession, raMasterApi);
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
        List<Integer> availableEndEntityProfileIds = new ArrayList<>();
        List<Integer> availableCertificateProfileIds = new ArrayList<>();
        List<Integer> availableCAIds = new ArrayList<>();
        for(SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : searchCertificatesRestRequest.getCriteria()) {
            final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
            switch (criteriaProperty) {
                case END_ENTITY_PROFILE:
                    availableEndEntityProfileIds = loadAuthorizedEndEntityProfileIds(authenticationToken, availableEndEntityProfileIds);
                    final Integer criteriaEndEntityProfileId = Integer.parseInt(searchCertificateCriteriaRestRequest.getValue());
                    if(!availableEndEntityProfileIds.contains(criteriaEndEntityProfileId)) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown end entity profile."
                        );
                    }
                    break;
                case CERTIFICATE_PROFILE:
                    availableCertificateProfileIds = loadAuthorizedCertificateProfileIds(authenticationToken, availableCertificateProfileIds);
                    final Integer criteriaCertificateProfileId = Integer.parseInt(searchCertificateCriteriaRestRequest.getValue());
                    if(!availableCertificateProfileIds.contains(criteriaCertificateProfileId)) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown certificate profile."
                        );
                    }
                    break;
                case CA:
                    availableCAIds = loadAuthorizedCAIds(authenticationToken, availableCAIds);
                    final Integer criteriaCAId = Integer.parseInt(searchCertificateCriteriaRestRequest.getValue());
                    if(!availableCAIds.contains(criteriaCAId)) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown CA."
                        );
                    }
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

    private List<Integer> loadAuthorizedEndEntityProfileIds(final AuthenticationToken authenticationToken, final List<Integer> availableEndEntityProfileIds) {
        if(availableEndEntityProfileIds.isEmpty()) {
            return super.getAuthorizedEndEntityProfileIds(authenticationToken);
        }
        return availableEndEntityProfileIds;
    }

    private List<Integer> loadAuthorizedCertificateProfileIds(final AuthenticationToken authenticationToken, final List<Integer> availableCertificateProfileIds) {
        if(availableCertificateProfileIds.isEmpty()) {
            return super.getAuthorizedCertificateProfileIds(authenticationToken);
        }
        return availableCertificateProfileIds;
    }

    private List<Integer> loadAuthorizedCAIds(final AuthenticationToken authenticationToken, final List<Integer> availableCAIds) {
        if(availableCAIds.isEmpty()) {
            return super.getAuthorizedCAIds(authenticationToken);
        }
        return availableCAIds;
    }
}
