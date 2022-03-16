/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.azure;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;

/**
 * I wrap building HttpClients and HttpRequests and make the necessary Proxy
 * calls when one is configured.
 */
public class HttpClientWithProxySupport {
    private Logger logger = Logger.getLogger(getClass());

    static {
        // see https://stackoverflow.com/questions/41505219/unable-to-tunnel-through-proxy-proxy-returns-http-1-1-407-via-https
        // and "Disable Basic authentication for HTTPS tunneling" here:
        // https://www.oracle.com/java/technologies/javase/8u111-relnotes.html
        // System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        // System.setProperty("jdk.http.auth.proxying.disabledSchemes", "");
        // It seems like a bad idea to do this automatically (and error prone, since setting
        // the property above needs to happen before any networks calls).  This should likely just be documented
        // and customers can set this on java startup.
    }

    final private String proxyUser;
    final private String proxyPassword;
    final private String proxyHost;
    final private int proxyPort;

    /**
     * This is only public for tests.  Use one of the static constructor methods.
     */
    public HttpClientWithProxySupport(String host, int port, String user, String password) {
        this.proxyUser = user;
        this.proxyPassword = password;
        this.proxyHost = host;
        this.proxyPort = port;
    }

    public static HttpClientWithProxySupport noProxy() {
        return new HttpClientWithProxySupport(null, -1, null, null);
    }

    public static HttpClientWithProxySupport openProxy(String host, int port) {
        return new HttpClientWithProxySupport(host, port, null, null);
    }

    public static HttpClientWithProxySupport basicAuthProxy(String host, int port, String user, String password) {
        return new HttpClientWithProxySupport(host, port, user, password);
    }

    protected CloseableHttpClient getClient() {
        if (proxyUser == null) {
            return HttpClients.createDefault();
        } else {
            // these need to be set correctly for proxying with basic authentication to work
            if (logger.isDebugEnabled()) {
                logger.debug("Current JDK tunneling setting: jdk.http.auth.tunneling.disabledSchemes="
                        + System.getProperty("jdk.http.auth.tunneling.disabledSchemes"));
                logger.debug("Current JDK proxying setting: jdk.http.auth.proxying.disabledSchemes="
                        + System.getProperty("jdk.http.auth.proxying.disabledSchemes"));
            }
            
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(new AuthScope(proxyHost, proxyPort), new UsernamePasswordCredentials(proxyUser, proxyPassword));
            logger.debug("Setting proxy credentials for " + proxyHost + ":" + proxyPort + " user = " + proxyUser);
            return HttpClients.custom().setDefaultCredentialsProvider(credsProvider).build();
        }
    }

    HttpPost getPost(String url) {
        HttpPost request = new HttpPost(url);
        if (proxyHost != null) {
            HttpHost proxy = new HttpHost(proxyHost, proxyPort, "http");
            request.setConfig(RequestConfig.custom().setProxy(proxy).build());
            logger.debug("Using proxy to call " + url);
        }
        return request;
    }

    HttpGet getGet(String url) {
        HttpGet request = new HttpGet(url);
        if (proxyHost != null) {
            HttpHost proxy = new HttpHost(proxyHost, proxyPort, "http");
            request.setConfig(RequestConfig.custom().setProxy(proxy).build());
            logger.debug("Using proxy to call " + url);
        }
        return request;
    }

    @Override
    public String toString() {
        if (proxyHost == null) {
            return "HttpClientWithProxySupport (no proxy)";
        } else if (proxyUser == null) {
            return "HttpClientWithProxySupport (not authenticated) [proxyHost=" + proxyHost + ", proxyPort=" + proxyPort + "]";
        } else {
            return "HttpClientWithProxySupport (not authenticated) [proxyHost=" + proxyHost + ", proxyPort=" + proxyPort + ", proxyUser=" + proxyUser
                    + "]";
        }
    }

}
