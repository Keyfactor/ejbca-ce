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
package org.cesecore.authentication.oauth;

import java.io.IOException;

/**
 * Helper, sends requests to oauth token providers to exchange code to token or to refresh token
 */
public class OauthRequestHelper {

    /**
     * Exchanges code to token
     * @param oAuthKeyInfo provider configurations
     * @param code code received from oauth provider after clients login
     * @param redirectUri ejbca url, used by provider to redirect response
     * @return OAuthGrantResponseInfo oauth provider response
     * @throws IOException
     */
    public static OAuthGrantResponseInfo sendTokenRequest( OAuthKeyInfo oAuthKeyInfo, String code, String redirectUri ) throws IOException {
        return sendRequest(code, false, oAuthKeyInfo, redirectUri);
    }

    /**
     * Exchanges refresh to authentication token
     * @param oAuthKeyInfo provider configurations
     * @param refreshToken refresh token received from oauth provider with previous token, what got expired
     * @param redirectUri ejbca url, used by provider to redirect response
     * @return OAuthGrantResponseInfo oauth provider response
     * @throws IOException
     */
    public static OAuthGrantResponseInfo sendRefreshTokenRequest(String refreshToken, OAuthKeyInfo oAuthKeyInfo, String redirectUri) throws IOException {
        return sendRequest(refreshToken, true, oAuthKeyInfo, redirectUri);
    }

    private static OAuthGrantResponseInfo sendRequest(String codeOrToken, boolean isRefresh, OAuthKeyInfo oAuthKeyInfo, String redirectUri) throws IOException {
        final OAuthTokenRequest request = new OAuthTokenRequest();
        request.setUri(oAuthKeyInfo.getTokenUrl());
        request.setClientId(oAuthKeyInfo.getClient());
        request.setClientSecret(oAuthKeyInfo.getClientSecretAndDecrypt());
        request.setRedirectUri(redirectUri);
        return request.execute(codeOrToken, isRefresh);
    }
}
