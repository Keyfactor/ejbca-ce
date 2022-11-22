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
package org.ejbca.core.ejb.authentication.web;

import java.security.cert.X509Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.config.OAuthConfiguration;

/**
 * Provides authentication for web service users.
 * 
 * @version $Id$
 */
@Local
public interface WebAuthenticationProviderSessionLocal extends AuthenticationProvider {

    /** @return an X509CertificateAuthenticationToken based on the provided client TLS certificate. */
    X509CertificateAuthenticationToken authenticateUsingClientCertificate(X509Certificate x509Certificate);

    /** @return a PublicAccessAuthenticationToken based on the provided info. */
    AuthenticationToken authenticateUsingNothing(String principal, boolean confidentialTransport);

    /** @return an OAuth2AuthenticationToken based on the given encoded token.  Returns null if token not valid. */
    AuthenticationToken authenticateUsingOAuthBearerToken(OAuthConfiguration oauthConfiguration, String encodedOauthBearerToken) throws TokenExpiredException;

    /** @return new OAuthGrantResponseInfo from oauth provider based on the given refresh token */
    OAuthGrantResponseInfo refreshOAuthBearerToken(OAuthConfiguration oauthConfiguration, String encodedOauthBearerToken, String refreshToken) throws TokenExpiredException;
}
