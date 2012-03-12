/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp;

import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

/**
 * This interface is used to generate OCSP responses.
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#OCSP_Response_Generation}
 * 
 * @version $Id$
 * 
 */
public interface OcspResponseGeneratorSession {

    /**
     * This method delivers an OCSP response to a given request, as provided in the byte[] parameter.
     * 
     * @param authenticationToken An authentication token for the user performing the operation.
     * @param request a byte array representing an encoded OCSPRequest.
     * @param requestCertificates An array of Certificates from the original HttpServletRequest
     * @param remoteAddress
     * @param remoteHost
     * 
     * @return a signed and encoded OCSPResponse
     * @throws AuthorizationDeniedException if authorization is denied for this operation.
     * @throws MalformedRequestException if the request byte array was invalid.
     */
    byte[] getOcspResponse(AuthenticationToken authenticationToken, byte[] request, X509Certificate[] requestCertificates, String remoteAddress,
            String remoteHost) throws AuthorizationDeniedException, MalformedRequestException;

    void reloadTokenAndChainCache(AuthenticationToken authenticationToken) throws CADoesntExistsException, AuthorizationDeniedException,
            IllegalCryptoTokenException;

}
