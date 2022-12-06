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
package org.ejbca.ui.web.rest.api.resource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;

/**
 * Helper class for search certificates RA requests.
 */
public class CertificateRestResourceUtil {

    /**
     * Authorizes the input search request for proper access references (End entity profile ids, Certificate profile ids and CA ids) inside a request.
     *
     * @param authenticationToken authentication token to use.
     * @param raMasterApi the RA master API reference.
     * @param searchCertificatesRestRequest input search request.
     * @throws RestException In case of inaccessible reference usage.
     */
    public static void authorizeSearchCertificatesRestRequestReferences(
            final AuthenticationToken authenticationToken,
            final RaMasterApiProxyBeanLocal raMasterApi,
            final SearchCertificateCriteriaRequest searchCertificatesRestRequest,
            final Map<Integer, String> availableEndEntityProfiles,
            final Map<Integer, String> availableCertificateProfiles,
            final Map<Integer, String> availableCAs
    ) throws RestException {
        
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
    
    public static Map<Integer, String> loadAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final RaMasterApiProxyBeanLocal raMasterApi) {
        return raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken);
    }

    public static Map<Integer, String> loadAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken, final RaMasterApiProxyBeanLocal raMasterApi) {
        return raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken);
    }

    public static Map<Integer, String> loadAuthorizedCAs(final AuthenticationToken authenticationToken, final RaMasterApiProxyBeanLocal raMasterApi) {
        final Map<Integer, String> availableCAs = new HashMap<>();
        final List<CAInfo> caInfosList = raMasterApi.getAuthorizedCas(authenticationToken);
        for(final CAInfo caInfo : caInfosList) {
            availableCAs.put(caInfo.getCAId(), caInfo.getName());
        }
        return availableCAs;
    }

    private static Integer getKeyFromMapByValue(final Map<Integer, String> map, final String value) {
        for(Integer key : map.keySet()) {
            if(map.get(key).equals(value)) {
                return key;
            }
        }
        return null;
    }
}
