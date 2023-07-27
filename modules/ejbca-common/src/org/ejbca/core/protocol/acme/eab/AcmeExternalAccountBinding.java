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
package org.ejbca.core.protocol.acme.eab;

import org.cesecore.accounts.AccountBinding;
import org.ejbca.configdump.ConfigDumpItemAware;
import org.ejbca.core.protocol.acme.AcmeProblemException;

/**
 * Base interface for all ACME external account bindings (EAB).
 * 
 * https://tools.ietf.org/html/rfc8555#section-7.3.4 
 */
public interface AcmeExternalAccountBinding extends AccountBinding, ConfigDumpItemAware {

    static final String TYPE_NAME = "ACME_EXTERNAL_ACCOUNT_BINDING";
    
    /**
     * Parses the EAB request ({@link Acme}. The RFC8555 compliant EAB 
     * implementation uses a JWS protected message. Other implementation 
     * may use their individual message format. 
     * 
     * https://tools.ietf.org/html/rfc8555#section-7.3.4
     * 
     * "externalAccountBinding": {
     *    "protected": base64url({
     *      "alg": "HS256",
     *      "kid": // key identifier from CA //,
     *      "url": "https://example.com/acme/new-account"
     *    }),
     *   "payload": base64url(// same as in "jwk" above //),
     *   "signature": // MAC using MAC key from CA //
     *  }
     * 
     * @param request the ACME protected request.
     * @param requestUrl the ACME newAccount URL.
     * @param jwk the base64 encoded account key in JWK form.
     * @param algorithmName JWS hash algorithm. I.e. HS256, HS384 or HS512. See {@link AcmeJwsHelper#getAvailableMacAlgorithms()}. Only used for EAB with HMAC protection.
     * @return the external account identifier.
     * @throws AcmeProblemException if the message could not be verified (technically, well-formed or by content).
     */
    String parseEabRequestMessage(Object request, String requestUrl, String jwk, String algorithmName) throws AcmeProblemException;
    
    /**
     * Clone has to be implemented instead of a copy constructor due to the 
     * fact that we'll be referring to implementations by this interface only. 
     * 
     * @return a deep copied clone of this account binding implementation.
     */
    AcmeExternalAccountBinding clone();
    
    /**
     * Returns true, if this implementation is the default implementation. 
     * @return
     */
    boolean isDefault();
}
