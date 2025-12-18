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
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.apache.http.HttpStatus;
import org.apache.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyFactorCommandSessionBean implements KeyFactorCommandSessionRemote {

    private static final Logger log = Logger.getLogger(KeyFactorCommandSessionBean.class);
    private static final String TOKEN_URL = "https://henrik-command.eastus2.cloudapp.azure.com:8444/realms/Keyfactor/protocol/openid-connect/token";
    private static final String CLIENT_ID = "Command-OIDC-Client";
    private static final String CLIENT_SECRET = "NDAbnVEZi4vJ";
    private static final String REST_API_URL = "https://henrik-command.eastus2.cloudapp.azure.com/KeyfactorAPI";
    private static final long TOKEN_EXPIRATION_TIME_MARGIN_MS = 10*60*1000; // 10 minutes
    private SSLContext sslContext;
    private String token;
    private long tokenExpirationTimeMs = 0L;

    @Override
    public void invalidateToken() {
        token = null;
        tokenExpirationTimeMs = 0L;
    }

    private boolean isTokenExpired() {
        return token == null || System.currentTimeMillis() >= tokenExpirationTimeMs;
    }

    private SSLContext getSslContext() throws KeyManagementException, NoSuchAlgorithmException {
        if (sslContext == null) {
            var trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
        }
        return sslContext;
    }

    private void requestNewToken() throws Exception {
        long now = System.currentTimeMillis();
        String formData = "client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8) +
                        "&client_secret=" + URLEncoder.encode(CLIENT_SECRET, StandardCharsets.UTF_8) +
                        "&grant_type=" + URLEncoder.encode("client_credentials", StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formData, StandardCharsets.UTF_8))
                .build();
        try (HttpClient client = HttpClient
                .newBuilder()
                .sslContext(getSslContext())
                .build()) {
            final var response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Map<?, ?> map = new ObjectMapper().readValue(response.body(), Map.class);
            token = String.valueOf(map.get("access_token"));
            int expiresInSeconds = (Integer)map.get("expires_in");
            tokenExpirationTimeMs = now + expiresInSeconds*1000 - TOKEN_EXPIRATION_TIME_MARGIN_MS;
        }
    }

    private String getToken() throws Exception {
        if (isTokenExpired()) {
            requestNewToken();
        }
        return token;
    }

    private HttpResponse<String> sendRequest(final String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(REST_API_URL+path))
                .header("Authorization", "Bearer "+getToken())
                .GET()
                .build();
        try (HttpClient client = HttpClient
                .newBuilder()
                .sslContext(getSslContext())
                .build()) {
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        }
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
    public Map<Integer, X509Certificate> getCertificates() throws Exception {
        final var response = sendRequest("/Certificates");
        if (response.statusCode() != HttpStatus.SC_OK) {
            throw new RuntimeException("Error getting certificates from KeyFactor Command: ("+response.statusCode()+") "+response.body());
        }
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> maps = new ObjectMapper().readValue(response.body(), List.class);
        final var certificates = new HashMap<Integer, X509Certificate>();
        for (var map : maps) {
            final int id = Integer.parseInt(map.get("Id").toString());
            final String contentBytes = (String) map.get("ContentBytes");
            certificates.put(id, getCertificateFromPem(getPem(contentBytes)));
        }
        return certificates;
    }

    @Override
    public X509Certificate getCertificate(final int id) throws Exception {
        final var response = sendRequest("/Certificates/"+id);
        if (response.statusCode() == HttpStatus.SC_NOT_FOUND) {
            return null;
        }
        if (response.statusCode() != HttpStatus.SC_OK) {
            throw new RuntimeException("Error getting certificate with id="+id+" from KeyFactor Command: ("+response.statusCode()+") "+response.body());
        }
        final String contentBytes = (new ObjectMapper().readValue(response.body(), Map.class).get("ContentBytes")).toString();
        final String pem = getPem(contentBytes);
        final var certificates = getCertificateListFromPem(pem);
        if (certificates.size() != 1) {
            throw new IllegalStateException("Expected exactly one certificate, got "+certificates.size());
        }
        return certificates.get(0);
    }

}
