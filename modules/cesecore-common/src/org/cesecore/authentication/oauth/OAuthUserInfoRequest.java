/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import com.keyfactor.util.FileTools;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.mime.MIME;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * Requests UserInfo. See <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 incorporating errata set 2 section 5.3</a>.
 *
 */
public class OAuthUserInfoRequest {

    private static final Logger log = Logger.getLogger(OAuthUserInfoRequest.class);

    private int timeoutMillis = 20_000;
    private int maxResponseBytes = 1024*1024; // 1 MiB
    private String uri;

    public int getTimeoutMillis() {
        return timeoutMillis;
    }

    public void setTimeoutMillis(final int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    public int getMaxResponseBytes() {
        return maxResponseBytes;
    }

    /** Sets the maximum response size (in bytes) from the authorization server. Default: 1 MiB. */
    public void setMaxResponseBytes(final int maxResponseBytes) {
        this.maxResponseBytes = maxResponseBytes;
    }

    public String getUri() {
        return uri;
    }

    /** Sets the URI of the userinfo endpoint. Must include the "/userinfo" part at the end. */
    public void setUri(final String uri) {
        this.uri = uri;
    }

    /**
     * Requests the UserInfo from the server.
     *
     * @param bearerToken Bearer token used in the authorization header of the request.
     * @return Response object with the claims from the userinfo endpoint.
     * @throws IOException On network errors or malformed server response.
     */
    public OAuthUserInfoResponse execute(final String bearerToken) throws IOException {
        final RequestConfig reqcfg = RequestConfig.custom()
                .setConnectionRequestTimeout(timeoutMillis)
                .setConnectTimeout(timeoutMillis)
                .setSocketTimeout(timeoutMillis)
                .build();
        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .disableConnectionState()
                .disableCookieManagement()
                .disableRedirectHandling()
                .setDefaultRequestConfig(reqcfg)
                .setUserTokenHandler(null)
                .useSystemProperties()
                .build()) {
            return execute(bearerToken, httpClient);
        }
    }

    /**
     * Requests the UserInfo from the server.
     *
     * @param bearerToken Bearer token used in the authorization header of the request.
     * @param httpClient The HttpClient to use for the request.
     * @return Response object with the claims from the userinfo endpoint.
     * @throws IOException On network errors or malformed server response.
     */
    public OAuthUserInfoResponse execute(final String bearerToken, final CloseableHttpClient httpClient) throws IOException {    
        final HttpGet get = new HttpGet();
        get.setHeader("Authorization", "Bearer " + bearerToken);
        
        try {
            get.setURI(new URI(uri));
        } catch (URISyntaxException e) {
            log.warn("UserInfo URL is malformed: " + uri);
            throw new IllegalStateException(e);
        }

        try (CloseableHttpResponse response = httpClient.execute(get)) {
            if (response.getStatusLine().getStatusCode() != 200) {
                final HttpEntity entity = response.getEntity();
                if (entity != null) {
                    final byte[] responseBytes = FileTools.readStreamToByteArray(entity.getContent(), -1, maxResponseBytes);
                    String content = new String(responseBytes, StandardCharsets.UTF_8);
                    log.info("Failed to get userinfo from server. HTTP status code " + response.getStatusLine().getStatusCode()
                            + " reason: " + response.getStatusLine().getReasonPhrase()
                            + " response content " + content);
                }
                throw new IOException("Failed to get userinfo from userinfo endpoint. HTTP status code " + response.getStatusLine().getStatusCode());
            }
            
            final Header[] contentType = response.getHeaders(MIME.CONTENT_TYPE);
            if (contentType == null || contentType.length != 1) {
                throw new IOException("Missing Content-Type header from userinfo response.");
            }            
            final HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw new IOException("Received empty HTTP response from userinfo endpoint.");
            }
            
            final byte[] responseBytes = FileTools.readStreamToByteArray(entity.getContent(), -1, maxResponseBytes);
            final JSONParser parser = new JSONParser();
            final OAuthUserInfoResponse userInfoResponse = new OAuthUserInfoResponse();
            
            final String mimeType = contentType[0].getValue().toLowerCase(Locale.ROOT);
            if (mimeType.matches("application/json( *; *charset *= *utf-8)?")) {
                try {
                    final JSONObject json = (JSONObject) parser.parse(new String(responseBytes, StandardCharsets.UTF_8));
                    userInfoResponse.setSubject((String) json.get("sub"));
                    userInfoResponse.setClaims(json.toJSONString());
                } catch (ParseException e) {
                    throw new IOException("Failed to parse JSON response from userinfo endpoint: " + e.getMessage(), e);
                }
            } else if (mimeType.matches("application/jwt")) {
                userInfoResponse.setResponseString(new String(responseBytes, StandardCharsets.UTF_8));
            } else {
                throw new IOException("Invalid MIME type on response from userinfo endpoint: " + mimeType);
            }

            return userInfoResponse;
        }
    }

}
