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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

public class AzureManagedIdentityAuthenticator extends AzureAuthenticator {
    private Logger logger = Logger.getLogger(getClass());
    final private HttpClientWithProxySupport client;

    public AzureManagedIdentityAuthenticator(String azureLoginUrl, HttpClientWithProxySupport client) {
        super(azureLoginUrl);
        this.client = client;
    }

    @Override
    public BearerToken getBearerTokenForResource(String resource) throws IOException, AzureException {
        if (logger.isDebugEnabled()) {
            logger.debug("Retrieving bearer token using managed identity.  Resource = " + resource);
        }

        String url = "http://169.254.169.254/metadata/identity/oauth2/token";
        try (CloseableHttpClient httpClient = client.getClient()) {
            //@formatter:off
            final URI managedIdentityUrl = new URIBuilder(url)
                    .setParameter("api-version", "2018-02-01")
                    .setParameter("resource", resource)
                    .build();
            //@formatter:on
            logger.debug("Created managed identity url: " + managedIdentityUrl.toString());
            HttpGet request = new HttpGet(managedIdentityUrl);
            request.setHeader("Metadata", "true");

            try (CloseableHttpResponse response = httpClient.execute(request); InputStream content = response.getEntity().getContent()) {
                logger.debug(response.getStatusLine());
                if (response.getStatusLine().getStatusCode() < 200 || response.getStatusLine().getStatusCode() >= 300) {
                    String message = "Error getting bearer token from " + url + ".  " + response.getStatusLine().getReasonPhrase();
                    logger.error(message);
                    if (content != null && logger.isDebugEnabled()) {
                        logger.debug(IOUtils.toString(content, StandardCharsets.UTF_8));
                    }
                    throw new AzureException(message);
                }

                JSONObject parsed = (JSONObject) JSONValue.parse(new InputStreamReader(content));
                String accessToken = (String) parsed.get("access_token");
                Long expiresIn = (Long) parsed.get("expires_in");
                return new BearerToken(accessToken, Instant.now().plusSeconds(expiresIn));
            }
        } catch (URISyntaxException e) {
            logger.error("Unexpected error creating url from " + url, e);
            throw new AzureException("Unexpected error creating url from " + url, e);
        }
    }

    @Override
    public String toString() {
        return "AzureManagedIdentityAuthenticator [client=" + client + "]";
    }

}
