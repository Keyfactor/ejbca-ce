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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

/**
 * I get bearer tokens for Azure access using a certificate and private key
 * (which should be registered with Azure under "Azure Active Directory/App
 * registrations/<client ID>/Certificates & Secrets"
 */
public class AzureCertificateAuthenticator extends AzureAuthenticator {
    private Logger logger = Logger.getLogger(getClass());

    private final String tenantID;
    private final String clientID;
    private final X509Certificate clientCertificate;
    private final PrivateKey clientKey;
    private final HttpClientWithProxySupport client;

    public AzureCertificateAuthenticator(String azureLoginUrl, String tenantID, String clientID, X509Certificate clientCertificate, PrivateKey clientKey,
            HttpClientWithProxySupport client) {
        super(azureLoginUrl);
        this.tenantID = tenantID;
        this.clientID = clientID;
        this.clientCertificate = clientCertificate;
        this.clientKey = clientKey;
        this.client = client;
    }

    @Override
    public BearerToken getBearerTokenForResource(String resource) throws IOException, AzureException {
        String[] scopes = new String[] {
                resource, "openid", "profile", "offline_access"
        };

        final String oauthUrl = getAzureLoginUrl() + tenantID + "/oauth2/v2.0/token";
        if (logger.isDebugEnabled()) {
            logger.debug("Retrieving bearer token from:" + oauthUrl + " for tenant " + tenantID + " client " + clientID + " using a secret.  Scopes: "
                    + Arrays.toString(scopes));
        }

        String jwtString;
        try {
            jwtString = getJwtString(oauthUrl, clientID, 60, clientKey, clientCertificate);
            if (logger.isDebugEnabled()) {
                logger.debug("JWT for Intune oauth:" + jwtString);
            }
        } catch (CertificateEncodingException | NoSuchAlgorithmException | JOSEException e) {
            throw new IOException("Unable to create JWT string.", e);
        }

        try (CloseableHttpClient httpClient = client.getClient()) {
            final HttpPost request = client.getPost(oauthUrl);
            final ArrayList<NameValuePair> parameters = new ArrayList<>();
            parameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
            parameters.add(new BasicNameValuePair("client_id", clientID));
            parameters.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            parameters.add(new BasicNameValuePair("client_assertion", jwtString));
            parameters.add(new BasicNameValuePair("scope", String.join(" ", scopes)));
            request.setEntity(new UrlEncodedFormEntity(parameters));
            try (CloseableHttpResponse response = httpClient.execute(request); InputStream content = response.getEntity().getContent()) {
                logger.debug(response.getStatusLine());
                if (response.getStatusLine().getStatusCode() < 200 || response.getStatusLine().getStatusCode() >= 300) {
                    String message = "Error getting bearer token from " + oauthUrl + ".  " + response.getStatusLine().getReasonPhrase();
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
        }
    }

    /**
     * Given the audience, client id, time-to-live and credentials, create JWT
     * encoded as a string to send to an OAUTH2-enabled API.
     * 
     * @param jwtAudience
     *            The URL we are authenticating to
     * @param clientId
     *            Our client ID
     * @param tokenLifetimeSeconds
     *            How long should this token be valid in seconds
     * @param key
     *            Authentication key
     * @param certificate
     *            Authentication certificate
     * @return The JWT encoded as a string
     * @throws CertificateEncodingException
     *             certificate is not formatted correctly
     * @throws NoSuchAlgorithmException
     *             Unexpected error
     * @throws JOSEException
     *             Error formatting JWT
     */
    @SuppressWarnings("deprecation")
    private static String getJwtString(String jwtAudience, String clientId, int tokenLifetimeSeconds, final PrivateKey key,
            final X509Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException, JOSEException {
        final long time = System.currentTimeMillis();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience(Collections.singletonList(jwtAudience)).issuer(clientId)
                .jwtID(UUID.randomUUID().toString()).notBeforeTime(new Date(time)).expirationTime(new Date(time + tokenLifetimeSeconds * 1000))
                .subject(clientId).build();

        JWSHeader.Builder builder = new Builder(JWSAlgorithm.RS256);
        List<com.nimbusds.jose.util.Base64> certs = new ArrayList<com.nimbusds.jose.util.Base64>();
        certs.add(new com.nimbusds.jose.util.Base64(java.util.Base64.getEncoder().encodeToString(certificate.getEncoded())));
        builder.x509CertChain(certs);
        String certHash = java.util.Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded()));
        builder.x509CertThumbprint(new Base64URL(certHash));
        SignedJWT jwt = new SignedJWT(builder.build(), claimsSet);
        jwt.sign(new RSASSASigner(key));
        String jwtString = jwt.serialize();
        return jwtString;
    }

    @Override
    public String toString() {
        return "AzureCertificateAuthenticator [tenantID=" + tenantID + ", clientID=" + clientID + ", clientCertificate.subject="
                + clientCertificate.getSubjectX500Principal() + ", client=" + client + "]";
    }

}
