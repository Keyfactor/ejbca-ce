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
import com.keyfactor.util.CertTools;
import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.apache.http.HttpStatus;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyFactorCommandSessionBean implements KeyFactorCommandSessionRemote {

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
    private static Map<String, Token> tokens;

    @EJB
    GlobalConfigurationSessionLocal globalConfigurationSession;

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

    private OAuthKeyInfo getOAuthKeyInfo(final String oAuthProvider) {
        String errorMessage = "There is no Default Trusted OAuth Provider selected.";
        final var configurationBase = globalConfigurationSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        if (configurationBase == null) {
            throw new RuntimeException(errorMessage);
        }
        final Map<String, OAuthKeyInfo> map = ((OAuthConfiguration)configurationBase).getOauthKeys();
        OAuthKeyInfo oAuthKeyInfo =
                map == null ?
                    null :
                    map.get(oAuthProvider);
        if (oAuthKeyInfo == null) {
            throw new RuntimeException("There is no OAuthProvider with the name \""+oAuthProvider+"\".");
        }
        return oAuthKeyInfo;
    }

    @Override
    public void invalidateToken(final String oAuthProvider) {
        try {
            lock.lock();
            tokens.remove(oAuthProvider);
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

    private void write(final URLConnection urlConnection, final String message) throws IOException {
        try (final OutputStream outputStream = urlConnection.getOutputStream()) {
            outputStream.write(message.getBytes(StandardCharsets.UTF_8));
        }
    }

    private RestResponse doSendRequest(final String method, final String urlString, final String contentType, final String requestBody, final String authorization) throws IOException {
        final URL url = URI.create(urlString).toURL();
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);
            connection.setRequestProperty("Content-Type", contentType);
            connection.setRequestProperty("Authorization", authorization);
            if (requestBody != null) {
                connection.setDoOutput(true);
                write(connection, requestBody);
            }
            final int statusCode = connection.getResponseCode();
            final InputStream inputStream = statusCode >= HttpStatus.SC_OK && statusCode < HttpStatus.SC_BAD_REQUEST ?
                    connection.getInputStream() :
                    connection.getErrorStream();
            String body = read(inputStream);
            return new RestResponse(statusCode, body);
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
        final var restResponse = doSendRequest("POST", url, "application/x-www-form-urlencoded", formData, null);
        restResponse.verifySuccess("Failed to request a new Token.");
        return restResponse.body();
    }

    private Token getNewToken(final OAuthKeyInfo oAuthKeyInfo) throws Exception {
        long now = System.currentTimeMillis();
        String formData = "client_id=" + URLEncoder.encode(oAuthKeyInfo.getClient(), StandardCharsets.UTF_8) +
                        "&client_secret=" + URLEncoder.encode(oAuthKeyInfo.getClientSecret(), StandardCharsets.UTF_8) +
                        "&grant_type=" + URLEncoder.encode("client_credentials", StandardCharsets.UTF_8);
        final String responseBody = sendTokenRequest(oAuthKeyInfo.getTokenUrl(), formData);
        Map<?, ?> map = new ObjectMapper().readValue(responseBody, Map.class);
        final var token = String.valueOf(map.get("access_token"));
        int expiresInSeconds = (Integer)map.get("expires_in");
        final var expirationTimeMs = now + expiresInSeconds*1000 - TOKEN_EXPIRATION_TIME_MARGIN_MS;
        return new Token(token, expirationTimeMs);
    }

    private Token getExisistingOrNewToken(final String oAuthProvider, final OAuthKeyInfo oAuthKeyInfo) throws Exception {
        try {
            lock.lock();
            Token token = tokens.get(oAuthProvider);
            if (isTokenExpired(token)) {
                token = getNewToken(oAuthKeyInfo);
                tokens.put(oAuthProvider, token);
            }
            return token;
        }
        finally {
            lock.unlock();
        }
    }

    private RestResponse sendApiRequest(final String oAuthProvider, final String path) throws Exception {
        final var oAuthKeyInfo = getOAuthKeyInfo(oAuthProvider);
        final Token token = getExisistingOrNewToken(oAuthProvider, oAuthKeyInfo);
        return doSendRequest("GET", oAuthKeyInfo.getUrl()+path, null, null, "Bearer "+ token.token());
    }

    private List<X509Certificate> getCertificateListFromPem(String pem) throws CertificateParsingException {
        return CertTools.getCertsFromPEM(new ByteArrayInputStream(pem.getBytes()), X509Certificate.class);
    }

    private X509Certificate getCertificateFromPem(String pem) throws CertificateParsingException {
        var list = getCertificateListFromPem(pem);
        if (list.size() != 1) {
            throw new IllegalStateException("Expected exactly one certificate, got "+list.size());
        }
        return list.get(0);
    }

    private String getPem(final String contentBytes) {
        return CertTools.BEGIN_CERTIFICATE + "\n" +
                contentBytes.replace("\r", "") + "\n" +
                CertTools.END_CERTIFICATE;
    }

    @Override
    public Map<Integer, X509Certificate> getCertificates(final String oAuthProvider) throws Exception {
        final var restResponse = sendApiRequest(oAuthProvider, "/Certificates");
        restResponse.verifySuccess("Failed to get certificates from KeyFactor Command.");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> maps = new ObjectMapper().readValue(restResponse.body, List.class);
        final var certificates = new HashMap<Integer, X509Certificate>();
        for (var map : maps) {
            final int id = Integer.parseInt(map.get("Id").toString());
            final String contentBytes = (String) map.get("ContentBytes");
            certificates.put(id, getCertificateFromPem(getPem(contentBytes)));
        }
        return certificates;
    }

    @Override
    public X509Certificate getCertificate(final String oAuthProvider, final int id) throws Exception {
        final var restResponse = sendApiRequest(oAuthProvider, "/Certificates/"+id);
        if (restResponse.httpStatus() == HttpStatus.SC_NOT_FOUND) {
            return null;
        }
        restResponse.verifySuccess("Failed to get certificate with id=" + id + " from KeyFactor Command.");
        final String contentBytes = (new ObjectMapper().readValue(restResponse.body, Map.class).get("ContentBytes")).toString();
        final String pem = getPem(contentBytes);
        final var certificates = getCertificateListFromPem(pem);
        if (certificates.size() != 1) {
            throw new IllegalStateException("Expected exactly one certificate, got "+certificates.size());
        }
        return certificates.get(0);
    }

}
