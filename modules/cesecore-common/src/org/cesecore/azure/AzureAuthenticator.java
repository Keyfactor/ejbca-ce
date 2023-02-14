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
package org.cesecore.azure;

import java.io.IOException;
import java.time.Instant;

/**
 * Base interface for credentials used to get the Bearer token to authenticate
 * to Azure REST API calls.
 */
public abstract class AzureAuthenticator {
    public static final String DEFAULT_AZURE_LOGIN_URL = "https://login.microsoftonline.com/";

    /**
     * I should be put in the Authentication header of an HTTP request to authenticate to an 
     * OAuth-secured API endpoint.
     */
    public static class BearerToken {

        private static final long EXPIRATION_WINDOW_SECONDS = 10;
        private final String token;
        private Instant expiresAt;

        public BearerToken(String token, Instant expiresAt) {
            this.token = token;
            this.expiresAt = expiresAt;
        }

        public String getToken() {
            return token;
        }

        public boolean isExpired() {
            return Instant.now().minusSeconds(EXPIRATION_WINDOW_SECONDS).isAfter(expiresAt);
        }
    }

    // this should end in a '/'
    final private String azureLoginUrl;

    public AzureAuthenticator(String azureLoginUrl) {
        if (!azureLoginUrl.endsWith("/"))
            azureLoginUrl += "/";
        this.azureLoginUrl = azureLoginUrl;
    }

    abstract public BearerToken getBearerTokenForResource(String resource) throws IOException, AzureException;

    protected String getAzureLoginUrl() {
        return azureLoginUrl;
    }
}