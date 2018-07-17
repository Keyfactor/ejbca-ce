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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * General service layer to support REST resource operations.
 *
 * @version $Id: RestService.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class RestService {

    @EJB
    protected RaMasterApiProxyBeanLocal raMasterApi;

    public RestService() {
    }

    /**
     * Returns the map of End Entity Profiles (id, name) accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of End Entity Profile Ids.
     */
    public Map<Integer, String> getAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken) {
        return raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken);
    }

    /**
     * Returns the map of Certificate Profiles (id, name) accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of Certificate Profile Ids.
     */
    public Map<Integer, String> getAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken) {
        return raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken);
    }

    /**
     * Returns the map of CAs (id, name) accessible within given authentication token.
     *
     * @param authenticationToken authentication token.
     * @return The list of CA Ids.
     */
    public Map<Integer, String> getAuthorizedCAs(final AuthenticationToken authenticationToken) {
        final Map<Integer, String> authorizedCAIds = new HashMap<>();
        final List<CAInfo> caInfosList = raMasterApi.getAuthorizedCas(authenticationToken);
        for(final CAInfo caInfo : caInfosList) {
            authorizedCAIds.put(caInfo.getCAId(), caInfo.getName());
        }
        return authorizedCAIds;
    }
}
