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
package org.ejbca.core.protocol.acme;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.config.AcmeConfiguration;
import org.ejbca.core.protocol.acme.eab.AcmeExternalAccountBinding;

/**
 * ACME configuration handling business logic.
 */
@Local
public interface AcmeConfigurationSessionLocal {

    /**
     * Get the ACME Configuration settings for the requested alias.
     * @param authenticationToken an authentication token authorizing the retrieval of the end entity profile and CAA identifiers
     * @param configurationAlias (allows the direct path param form ending in '/')
     * @return the requested Acme Configuration
     * @throws AcmeProblemException if the requested configuration does not exist
     */
    AcmeConfiguration getAcmeConfiguration(AuthenticationToken authenticationToken, String configurationAlias) throws AcmeProblemException;
    
    /**
     * Parses the EAB request {@link AcmeExternalAccountBinding}.
     * 
     * @param authenticationToken the authentication token.
     * @param alias the configuration alias.
     * @param requestUrl the ACME newAccount URL.
     * @param requestJwk the base64 encoded account key in JWK form.
     * @param eabRequestJsonString the EAB request as JSON string.
     * @return the external account identifier.
     * @throws AcmeProblemException if the message could not be verified (technically, well-formed or by content).
     */
    String parseAcmeEabMessage(AuthenticationToken authenticationToken, String alias, String requestUrl, String requestJwk,
            String eabRequestJsonString) throws AcmeProblemException;

}