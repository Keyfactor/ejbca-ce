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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;

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
    public static HttpResponse sendRequest(final HttpUriRequest request, final Integer timeoutMillis, final X509Certificate serverCertificate, final X509Certificate clientCertificate, final KeyPair clientKeyPair) throws IOException {
        final HttpClientBuilder clientBuilder = HttpClientBuilder.create();
        if (timeoutMillis != null) {
            final RequestConfig reqcfg = RequestConfig.custom()
                .setConnectionRequestTimeout(timeoutMillis)
                .setConnectTimeout(timeoutMillis)
                .setSocketTimeout(timeoutMillis)
                .build();
            clientBuilder.setDefaultRequestConfig(reqcfg);
        }
        if (serverCertificate != null) {
            try {
                final KeyStore trustKeyStore = KeyStore.getInstance("JKS");
                trustKeyStore.load(null);
                trustKeyStore.setCertificateEntry("caCert", serverCertificate);
                final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustKeyStore);
                final KeyStore clientCertKeyStore = KeyStore.getInstance("JKS");
                clientCertKeyStore.load(null);
                if (clientCertificate != null) {
                    clientCertKeyStore.setCertificateEntry("clientCert", clientCertificate);
                    clientCertKeyStore.setKeyEntry("clientCert", clientKeyPair.getPrivate(), "foo123".toCharArray(), new Certificate[] { clientCertificate });
                }
                final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                keyManagerFactory.init(clientCertKeyStore, "foo123".toCharArray());
                final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
                final SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext, new String[]{ "TLSv1.2" }, null, new NoopHostnameVerifier());
                final HttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(
                        RegistryBuilder.<ConnectionSocketFactory>create()
                                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                                .register("https", sslConnectionSocketFactory).build()
                );
                clientBuilder.setConnectionManager(connManager);
            } catch (GeneralSecurityException e) {
                throw new IOException("Failed to initialize key stores: " + e.getMessage(), e);
            }
        }
        final HttpClient client = clientBuilder.build();
        if (log.isDebugEnabled()) {
            log.debug("Sending " + request.getMethod() + " request with URL '" + request.getURI() + "'");
        }
        return client.execute(request);
    }

    public static HttpResponse sendRequest(final HttpUriRequest request, final Integer timeoutMillis) throws IOException {
        return sendRequest(request, timeoutMillis, null, null, null);
    }

    public static HttpResponse sendGetRequest(final String url, final Integer timeoutMillis) throws IOException {
        // For an example on how to send a POST request (with an request body), see HttpPostTimeoutInvoker in EJBCA enterprise edition
        final HttpGet get = new HttpGet(url);
        get.setHeader("User-Agent", USER_AGENT);
        return sendRequest(get, timeoutMillis);
    }

    public static HttpResponse sendGetRequest(final String url, final X509Certificate serverCertificate, final X509Certificate clientCertificate, final KeyPair clientKeyPair) throws IOException {
        final HttpGet get = new HttpGet(url);
        get.setHeader("User-Agent", USER_AGENT);
        return sendRequest(get, DEFAULT_TIMEOUT, serverCertificate, clientCertificate, clientKeyPair);
    }
    
    public static HttpResponse sendGetRequest(final String url) throws IOException {
        return sendGetRequest(url, DEFAULT_TIMEOUT);
    }

    /** Returns the response body of a HTTP request */
    public static byte[] getBytesFromResponse(final HttpResponse resp) {
        final HttpEntity body = resp.getEntity();
        assertNotNull("Response body should not be null.", body);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(body.getContent(), baos);
        } catch (UnsupportedOperationException | IOException e) {
            throw new IllegalStateException("Failed to read HTTP response body: " + e.getMessage(), e);
        }
        return baos.toByteArray();
    }

    /**
     * Checks that an HTTP response resulted in a file download of the given MIME type and with the given filename.
     * @param resp HTTP response
     * @param expectedContentType Expected content MIME type
     * @param expectedFilename Expected filename of download
     */
    public static void assertValidDownloadResponse(final HttpResponse resp, final String expectedContentType, final String expectedFilename) {
        assertEquals("Response code", 200, resp.getStatusLine().getStatusCode());
        assertNotNull("No response body was sent", resp.getEntity());
        final String contentType = resp.getEntity().getContentType().getValue();
        assertTrue("Wrong content type: " + contentType, StringUtils.startsWith(contentType, expectedContentType));
        final Header header = resp.getFirstHeader("Content-disposition");
        assertNotNull("Missing Content-disposition header.", header);
        assertEquals("attachment; filename=\"" + expectedFilename + "\"", header.getValue());
    }

    /**
     * Creates a client certificate with a new role with superadmin access.
     * @param testName Name that will be used for the role name, end entity name and CN attribute.
     */
    public static X509Certificate setUpClientCertificate(final String testName, final PublicKey publicKey) {
        log.trace(">setUpClientCertificate");
        final RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(testName);
        final CAInfo caInfo = CaTestUtils.getClientCertCaInfo(admin);
        log.debug("Issuing client certificate using CA '" + caInfo.getName() + "'");
        final EndEntityInformation user = new EndEntityInformation(testName, "CN="+testName+",O=WebTestUtils", caInfo.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        final RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        try {
            final X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(
                    admin, user, req, X509ResponseMessage.class, new CertificateGenerationParams());
            if (!ResponseStatus.SUCCESS.equals(resp.getStatus())) {
                fail("Failed to issue client certificate: " + resp.getFailText());
            }
            final X509Certificate clientCertificate = (X509Certificate) resp.getCertificate();
            assertNotNull("Returned client certificate was null", clientCertificate);
            // Add authorization rules for this client SSL certificate
            roleInitSession.initializeAccessWithCert(admin, testName, clientCertificate);
            roleInitSession.createRoleAndAddCertificateAsRoleMember(clientCertificate, null, testName, null, null);
            log.trace("<setUpClientCertificate");
            return clientCertificate;
        } catch (RoleExistsException | CustomCertificateSerialNumberException | IllegalKeyException | CADoesntExistsException | CertificateCreateException |
                CryptoTokenOfflineException | SignRequestSignatureException | IllegalNameException | CertificateRevokeException | CertificateSerialNumberException |
                IllegalValidityException | CAOfflineException | InvalidAlgorithmException | AuthorizationDeniedException | CertificateExtensionException |
                RoleNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void cleanUpClientCertificate(final String testName) {
        final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(testName);
        try {
            roleSession.deleteRoleIdempotent(admin, null, testName);
        } catch (Exception e) {
            log.debug(e.getMessage());
        }
        try {
            endEntityManagementSession.deleteUser(admin, testName);
        } catch (Exception e) {
            log.debug(e.getMessage());
        }
        try {
            internalCertificateStoreSession.removeCertificatesByUsername(testName);
        } catch (Exception e) {
            log.debug(e.getMessage());
        }
    }

    /** Returns the certificate of the 'target.servercert.ca' CA, that is, the CA that issued the TLS server certificate */
    public static X509Certificate getServerCertificate() {
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("WebTestUtils");
        final CAInfo serverCaInfo = CaTestUtils.getServerCertCaInfo(admin);
        final List<Certificate> chain = serverCaInfo.getCertificateChain();
        return (X509Certificate) chain.get(0);
    }
}
