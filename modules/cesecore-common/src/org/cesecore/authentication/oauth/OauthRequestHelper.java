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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import com.google.common.base.Preconditions;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import org.apache.commons.lang3.tuple.Pair;
import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.cesecore.keybind.KeyBindingNotFoundException;
import org.cesecore.keys.token.KeyAndCertFinder;

/**
 * Helper, sends requests to oauth token providers to exchange code to token or to refresh token
 */
public class OauthRequestHelper {
    
    private KeyAndCertFinder keyBindingFinder;

    public OauthRequestHelper(KeyAndCertFinder keyBindingFinder) {
        this.keyBindingFinder = keyBindingFinder;
    }

    /**
     * Exchanges code to token
     * @param oAuthKeyInfo provider configurations
     * @param code code received from oauth provider after clients login
     * @param redirectUri ejbca url, used by provider to redirect response
     * @return OAuthGrantResponseInfo oauth provider response
     * @throws IOException
     * @throws KeyBindingNotFoundException 
     * @throws CryptoTokenOfflineException 
     */
    public OAuthGrantResponseInfo sendTokenRequest( OAuthKeyInfo oAuthKeyInfo, String code, String redirectUri ) throws IOException, CryptoTokenOfflineException, KeyBindingNotFoundException {
        return sendRequest(code, false, oAuthKeyInfo, redirectUri);
    }

    /**
     * Exchanges refresh to authentication token
     * @param oAuthKeyInfo provider configurations
     * @param refreshToken refresh token received from oauth provider with previous token, what got expired
     * @param redirectUri ejbca url, used by provider to redirect response
     * @return OAuthGrantResponseInfo oauth provider response
     * @throws IOException
     * @throws KeyBindingNotFoundException 
     * @throws CryptoTokenOfflineException 
     */
    public OAuthGrantResponseInfo sendRefreshTokenRequest(String refreshToken, OAuthKeyInfo oAuthKeyInfo, String redirectUri) throws IOException, CryptoTokenOfflineException, KeyBindingNotFoundException {
        return sendRequest(refreshToken, true, oAuthKeyInfo, redirectUri);
    }

    private OAuthGrantResponseInfo sendRequest(String codeOrToken, boolean isRefresh, OAuthKeyInfo oAuthKeyInfo, String redirectUri) throws IOException, CryptoTokenOfflineException, KeyBindingNotFoundException {
        final OAuthTokenRequest request = new OAuthTokenRequest();
        request.setUri(oAuthKeyInfo.getTokenUrl());
        request.setClientId(oAuthKeyInfo.getClient());
        if (oAuthKeyInfo.getKeyBinding() != null) {
            Preconditions.checkState(oAuthKeyInfo.getType() == OAuthProviderType.TYPE_AZURE, "OAuth cert authentication only supported for Azure");
            Pair<X509Certificate, PrivateKey> certificateAndKey = keyBindingFinder.find(oAuthKeyInfo.getKeyBinding())
                    .orElseThrow(() -> new KeyBindingNotFoundException(oAuthKeyInfo.getKeyBinding().toString()));
            request.setClientAssertionAudience(oAuthKeyInfo.getLoginServerUrl());
            request.setKey(certificateAndKey.getRight());
            request.setCertificate(certificateAndKey.getLeft());
        } else {
            request.setClientSecret(oAuthKeyInfo.getClientSecretAndDecrypt());
        }
        request.setRedirectUri(redirectUri);
        return request.execute(codeOrToken, isRefresh);
    }
}
