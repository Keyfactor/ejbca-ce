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
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

import javax.ejb.EJB;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * General service layer to support REST resource operations.
 *
 * @version $Id: RestService.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class RestService {

    @EJB
    protected RaMasterApiProxyBeanLocal raMasterApi;

    public RestService() {
    }

    /**
     * Returns the list of End Entity Profile Ids accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of End Entity Profile Ids.
     */
    public List<Integer> getAuthorizedEndEntityProfileIds(final AuthenticationToken authenticationToken) {
        final Map<Integer, String> availableEndEntityProfilesMap = raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken);
        return new ArrayList<>(availableEndEntityProfilesMap.keySet());
    }

    /**
     * Returns the list of Certificate Profile Ids accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of Certificate Profile Ids.
     */
    public List<Integer> getAuthorizedCertificateProfileIds(final AuthenticationToken authenticationToken) {
        final Map<Integer, String> availableCertificateProfilesMap = raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken);
        return new ArrayList<>(availableCertificateProfilesMap.keySet());
    }

    /**
     * Returns the list of CA Ids accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of CA Ids.
     */
    public List<Integer> getAuthorizedCAIds(final AuthenticationToken authenticationToken) {
        final List<Integer> authorizedCAIds = new ArrayList<>();
        final List<CAInfo> caInfosList = raMasterApi.getAuthorizedCas(authenticationToken);
        for(final CAInfo caInfo : caInfosList) {
            authorizedCAIds.add(caInfo.getCAId());
        }
        return authorizedCAIds;
    }
}
