/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.proxyca;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.apache.http.HttpStatus;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.kfenroll.ProxyCa;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyFactorCommandSessionBean implements KeyFactorCommandSessionRemote {

    private record OAuthInfo(String upstreamUrl, String tokenUrl, String clientName, String clientSecret) {
    }

    private record Token(String token, long expirationTimeMs) {
    }

    private record RestResponse(int httpStatus, String body) {

        public void verifySuccess(final String message) throws IOException {
            if (httpStatus != HttpStatus.SC_OK) {
                throw new IOException(message + ": (" + httpStatus + ") " + body);
            }
        }

    }

    private static final Logger log = Logger.getLogger(KeyFactorCommandSessionBean.class);
    private static final long TOKEN_EXPIRATION_TIME_MARGIN_MS = 10*60*1000; // 10 minutes
    private static Lock lock;
    private static SSLContext sslContext;
    private static Map<Integer, Token> tokens; // One token per CA.

    @EJB
    private CaSessionLocal caSession;

    @PostConstruct
    public void postConstruct() throws NoSuchAlgorithmException, KeyManagementException {
        lock = new ReentrantLock();
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] {
                new X509TrustManagerAcceptAll()
        }, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        tokens = new HashMap<>();
    }

    private ProxyCa getProxyCa(final Integer caId) {
        CAData caData = caSession.findById(caId);
        if (caData == null || caData.getCA() == null) {
            throw new RuntimeException("There is no CA with id "+caId);
        }
        try {
            return (ProxyCa)caData.getCA();
        }
        catch (ClassCastException e) {
            throw new RuntimeException("The CA with id " + caId + " is not a ProxyCa.", e);
        }
    }

    private OAuthInfo getOAuthInfo(ProxyCa proxyCa) {
        final String upstreamUrl  = Objects.requireNonNull(proxyCa.getEnrollWithCsrUrl(),  "Upstream URL is empty for the CA with id = "        + proxyCa.getCAId());
        final String tokenUrl     = Objects.requireNonNull(proxyCa.getOauthTokenUrl(),     "OAuth Token URL is empty for the CA with id = "     + proxyCa.getCAId());
        final String clientName   = Objects.requireNonNull(proxyCa.getOauthClientName(),   "OAuth Client Name is empty for the CA with id = "   + proxyCa.getCAId());
        final String clientSecret = Objects.requireNonNull(proxyCa.getOauthClientSecret(), "OAuth Client Secret is empty for the CA with id = " + proxyCa.getCAId());
        return new OAuthInfo(
                upstreamUrl,
                tokenUrl,
                clientName,
                clientSecret);
    }

    @Override
    public void invalidateToken(final Integer caId) {
        try {
            lock.lock();
            tokens.remove(caId);
        }
        finally {
            lock.unlock();
        }
    }

    private boolean isTokenExpired(Token token) {
        return token == null || System.currentTimeMillis() >= token.expirationTimeMs();
    }

    private String read(final InputStream inputStream) throws IOException {
        try {
            return new String(inputStream.readAllBytes());
        }
        finally {
            inputStream.close();
        }
    }

    private String getResponseBody(final HttpURLConnection connection, final int statusCode) throws IOException {
        if (statusCode == HttpStatus.SC_UNAUTHORIZED) {
            return null;
        }
        else {
            final InputStream inputStream = statusCode >= HttpStatus.SC_OK && statusCode < HttpStatus.SC_BAD_REQUEST ?
                    connection.getInputStream() :
                    connection.getErrorStream();
            return read(inputStream);
        }
    }

    private Response getResponse(final HttpURLConnection connection) throws IOException {
        final int statusCode = connection.getResponseCode();
        return new Response(statusCode, getResponseBody(connection, statusCode));
    }

    private void write(final URLConnection urlConnection, final String message) throws IOException {
        try (final OutputStream outputStream = urlConnection.getOutputStream()) {
            outputStream.write(message.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void debugSendParameters(final String method, final String url, final Map<String, String> headers, final String requestBody) {
        log.debug("Sending REST request:");
        log.debug("   method      = "+method);
        log.debug("   url         = "+url);
        if (headers != null && !headers.isEmpty()) {
            log.debug("   headers:");
            var keys = new TreeSet<>(headers.keySet());
            for (var key : keys) {
                log.debug("      "+key+" = "+headers.get(key));
            }
        }
        log.debug("   requestBody = "+requestBody);
    }

    private void debugResponse(final Response response) {
        log.debug("Received REST response:");
        log.debug("   httpStatus = " + response.httpStatus());
        log.debug("   body       = " + response.body());
    }

    private void setRequestProperties(final HttpURLConnection connection, final Map<String, String> headers) {
        if (headers != null) {
            for (var entry : headers.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
        }
    }

    private void setToken(final HttpURLConnection connection, final Token token) {
        if (token != null) {
            connection.setRequestProperty("Authorization", "Bearer " + token.token());
        }
    }

    private void setRequestBody(final HttpURLConnection connection, final String requestBody) throws IOException {
        if (requestBody != null) {
            connection.setDoOutput(true);
            write(connection, requestBody);
        }
    }

    private Response doSendRequest(final String method, final String url, Map<String, String> headers, final String requestBody, final Token token) throws IOException {
        if (log.isDebugEnabled()) {
            debugSendParameters(method, url, headers, requestBody);
        }
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
            connection.setRequestMethod(method);
            setRequestProperties(connection, headers);
            setToken(connection, token);
            setRequestBody(connection, requestBody);
            final var response = getResponse(connection);
            if (log.isDebugEnabled()) {
                debugResponse(response);
            }
            return response;
        }
        finally {
            try {
                if (connection != null) {
                    connection.disconnect();
                }
            }
            catch (Exception ignored) {
            }
        }
    }

    private String sendTokenRequest(final String url, final String formData) throws IOException {
        final var response = doSendRequest("POST", url, Map.of("Content-Type", "application/x-www-form-urlencoded"), formData, null);
        if (response.httpStatus() != HttpStatus.SC_OK) {
            throw new IOException("("+response.httpStatus()+"): Failed to request a new Token.");
        }
        return response.body();
    }

    private Token getNewToken(final OAuthInfo oAuthInfo) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Generating a new token.");
        }
        long now = System.currentTimeMillis();
        String formData = "client_id=" + URLEncoder.encode(oAuthInfo.clientName, StandardCharsets.UTF_8) +
                        "&client_secret=" + URLEncoder.encode(oAuthInfo.clientSecret, StandardCharsets.UTF_8) +
                        "&grant_type=" + URLEncoder.encode("client_credentials", StandardCharsets.UTF_8);
        final String responseBody = sendTokenRequest(oAuthInfo.tokenUrl, formData);
        Map<?, ?> map = new ObjectMapper().readValue(responseBody, Map.class);
        final var oauthToken = String.valueOf(map.get("access_token"));
        int expiresInSeconds = (Integer)map.get("expires_in");
        final var expirationTimeMs = now + expiresInSeconds*1000 - TOKEN_EXPIRATION_TIME_MARGIN_MS;
        final var token = new Token(oauthToken, expirationTimeMs);
        if (log.isDebugEnabled()) {
            log.debug("token.expirationTimeMs = "+token.expirationTimeMs());
        }
        return token;
    }

    private Token getExisistingOrNewToken(final Integer caId, final OAuthInfo oAuthInfo) throws Exception {
        try {
            lock.lock();
            Token token = tokens.get(caId);
            if (isTokenExpired(token)) {
                token = getNewToken(oAuthInfo);
                tokens.put(caId, token);
            }
            return token;
        }
        finally {
            lock.unlock();
        }
    }

    @Override
    public Response send(final Integer caId, final String method, final String path, final Map<String, String> headers, final String requestBody) throws Exception {
        var proxyCa = getProxyCa(caId);
        var oAuthInfo = getOAuthInfo(proxyCa);
        var token = getExisistingOrNewToken(caId, oAuthInfo);
        var response = doSendRequest(method, oAuthInfo.upstreamUrl()+path, headers, requestBody, token);
        if (response.httpStatus() == HttpStatus.SC_UNAUTHORIZED) {
            // Require a new token
            if (log.isDebugEnabled()) {
                log.debug("Token has expired. Requesting a new one.");
            }
            invalidateToken(caId);
            token = getExisistingOrNewToken(caId, oAuthInfo);
            response = doSendRequest(method, oAuthInfo.upstreamUrl()+path, headers, requestBody, token);
        }
        return response;
    }

}
