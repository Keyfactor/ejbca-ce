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
package org.cesecore;

import java.io.IOException;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.log4j.Logger;

/**
 * Utility methods to send HTTP requests
 * 
 * @version $Id$
 */
public final class WebTestUtils {

    private static final Logger log = Logger.getLogger(WebTestUtils.class);
    
    public final static String USER_AGENT = "EJBCA-Test/1.0";
    public final static int DEFAULT_TIMEOUT = 30000;
    
    private WebTestUtils() {}
    
    /**
     * Sends a HTTP request
     * @param request HttpGet or HttpPost object describing the request to send.
     * @param timeoutMillis timeout in milliseconds, or null to use Java default values.
     * @return response
     * @throws IOException if a connection failure etc. occurs
     */
    public static HttpResponse sendRequest(final HttpUriRequest request, final Integer timeoutMillis) throws IOException {
        final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        if (timeoutMillis != null) {
            final RequestConfig reqcfg = RequestConfig.custom()
                .setConnectionRequestTimeout(timeoutMillis)
                .setConnectTimeout(timeoutMillis)
                .setSocketTimeout(timeoutMillis)
                .build();
            clientBuilder.setDefaultRequestConfig(reqcfg);
        }
        final HttpClient client = clientBuilder.build();
        if (log.isDebugEnabled()) {
            log.debug("Sending " + request.getMethod() + " request with URL '" + request.getURI() + "'");
        }
        return client.execute(request);
    }
    
    public static HttpResponse sendGetRequest(final String url, final Integer timeoutMillis) throws IOException {
        // For an example on how to send a POST request (with an request body), see HttpPostTimeoutInvoker in EJBCA enterprise edition
        final HttpGet get = new HttpGet(url);
        get.setHeader("User-Agent", USER_AGENT);
        return sendRequest(get, timeoutMillis);
    }
    
    public static HttpResponse sendGetRequest(final String url) throws IOException {
        return sendGetRequest(url, DEFAULT_TIMEOUT);
    }
}
