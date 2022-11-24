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

import java.util.ArrayList;
import java.util.List;

/**
 * Class representing the list of authorized EEP for the current admin
 */
public class AuthorizedEEPsRestResponse {

    private List<EndEntityProfileRestResponse> endEntitieProfiles = new ArrayList<>();

    public AuthorizedEEPsRestResponse() {
        super();
    }

    public List<EndEntityProfileRestResponse> getEndEntitieProfiles() {
        return endEntitieProfiles;
    }

    public void setEndEntitieProfiles(List<EndEntityProfileRestResponse> endEntitieProfiles) {
        this.endEntitieProfiles = endEntitieProfiles;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static AuthorizedEEPsRestResponseBuilder builder() {
        return new AuthorizedEEPsRestResponseBuilder();
    }

    public static class AuthorizedEEPsRestResponseBuilder {

        private List<EndEntityProfileRestResponse> endEntitieProfiles;

        private AuthorizedEEPsRestResponseBuilder() {
        }

        public AuthorizedEEPsRestResponseBuilder setEndEntityProfiles(final List<EndEntityProfileRestResponse> endEntitieProfiles) {
            this.endEntitieProfiles = endEntitieProfiles;
            return this;
        }

        public AuthorizedEEPsRestResponse build() {
            final AuthorizedEEPsRestResponse authorizedEEPsRestResponse = new AuthorizedEEPsRestResponse();
            authorizedEEPsRestResponse.setEndEntitieProfiles(endEntitieProfiles);
            return authorizedEEPsRestResponse;
        }
    }
}
