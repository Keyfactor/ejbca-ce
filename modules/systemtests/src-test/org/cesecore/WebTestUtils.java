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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Utility methods to send HTTP requests
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
        assertEquals("Wrong response code (Message is: " + resp.getStatusLine().getReasonPhrase() + ")", 200, resp.getStatusLine().getStatusCode());
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
        final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        final RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(testName);
        final CAInfo caInfo = CaTestUtils.getClientCertCaInfo(admin);
        log.debug("Issuing client certificate using CA '" + caInfo.getName() + "'");
        final EndEntityInformation user = new EndEntityInformation(testName, "CN="+testName+",O=WebTestUtils", caInfo.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, null);
        user.setPassword("foo123");
        try {
            endEntityManagementSession.addUser(admin, user, false);
            final X509Certificate clientCertificate = (X509Certificate) signSession.createCertificate(admin, testName, "foo123", new PublicKeyWrapper(publicKey));
            assertNotNull("Returned client certificate was null", clientCertificate);
            // Add authorization rules for this client SSL certificate
            roleInitSession.initializeAccessWithCert(admin, testName, clientCertificate);
            roleInitSession.createRoleAndAddCertificateAsRoleMember(clientCertificate, null, testName, null, null);
            log.trace("<setUpClientCertificate");
            return clientCertificate;
        } catch (EjbcaException | CesecoreException | AuthorizationDeniedException | EndEntityProfileValidationException |
                WaitingForApprovalException | RoleExistsException | RoleNotFoundException e) {
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
            log.debug("Failed to clean up role: " + e.getMessage());
        }
        try {
            endEntityManagementSession.deleteUser(admin, testName);
        } catch (Exception e) {
            log.debug("Failed to clean up end entity: " + e.getMessage());
        }
        try {
            internalCertificateStoreSession.removeCertificatesByUsername(testName);
        } catch (Exception e) {
            log.debug("Failed to clean up certificate: " + e.getMessage());
        }
    }

    /**
     * Returns the certificate of the 'target.servercert.ca' CA, that is, the CA that issued the TLS server certificate
     * 
     * @return the X.509 certificate.
     */
    public static X509Certificate getServerCertificate() {
        final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("WebTestUtils");
        final CAInfo serverCaInfo = CaTestUtils.getServerCertCaInfo(admin);
        final List<Certificate> chain = serverCaInfo.getCertificateChain();
        return (X509Certificate) chain.get(0);
    }
    
    /**
     * Loads the keystore with the given path, or creates a new keystore and stores it under the given path.
     * 
     * @param path the absolute file path of the keystore.
     * @param pwd the keystore password.
     * @return the keystore.
     * 
     * @throws KeyStoreException any.
     * @throws IOException any.
     * @throws CertificateException any.
     * @throws NoSuchAlgorithmException any.
     */
    public static KeyStore initJksKeyStore(final String path, final String pwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final File file = new File(path);
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        if (file.exists()) {
            keyStore.load(new FileInputStream(file), pwd.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), pwd.toCharArray());
        }
        return keyStore;
    }
    
    /**
     * Inserts the CA certificate and the key pair and user certificate (if present) into the keystore with the given alias.
     * 
     * @param path the absolute file path of the keystore.
     * @param pwd the keystore password.
     * @param keystore the keystore.
     * @param alias the alias name for the objects to be inserted.
     * @param issuerCertificateBytes the CA certificate to be inserted.
     * @param keyPair the key pair to be inserted.
     * @param certificateBytes the certificate to be inserted.
     * 
     * @throws IOException any.
     * @throws CertificateException any.
     * @throws KeyStoreException any.
     * @throws NoSuchAlgorithmException any.
     */
    public static void importDataIntoJksKeystore(final String path, final String pwd, final KeyStore keystore, final String alias,
        final byte[] issuerCertificateBytes, final KeyPair keyPair, final byte[] certificateBytes
    ) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        // Add the certificate.  
        keystore.setCertificateEntry(alias, CertTools.getCertfromByteArray(issuerCertificateBytes, X509Certificate.class));
        // Add the key if it exists.
        if(keyPair != null) {
            final Certificate[] chain = { CertTools.getCertfromByteArray(certificateBytes, X509Certificate.class) };
            keystore.setKeyEntry(alias, keyPair.getPrivate(), pwd.toCharArray(), chain);
        }
        // Save the new keystore contents.
        final FileOutputStream fileOutputStream = new FileOutputStream(path);
        keystore.store(fileOutputStream, pwd.toCharArray());
        fileOutputStream.close();
    }
    
    /**
     * Returns a new trust manager factory with the keystore stored under the given path. If the keystore 
     * does not exists, a new keystore is generated and stored. The first CA certificate in the issuers 
     * CA chain found (for test usually self-signed ManagementCA) is added to the keystore.
     * 
     * TODO: Fix for CA chains > 1.
     * 
     * @param path the absolute file path of the keystore.
     * @param pwd the keystore password.
     * @param caInfo the CA info object of the CA certificate to be inserted (for test usually self-signed ManagementCA).
     * @return the trust manager factory.
     * 
     * @throws KeyStoreException any.
     * @throws CertificateException any.
     * @throws NoSuchAlgorithmException any.
     * @throws IOException any.
     */
    public static TrustManagerFactory createTrustManagerFactory(final String path, final String pwd, final CAInfo caInfo) 
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        final KeyStore keystore = initJksKeyStore(path, pwd);
        importDataIntoJksKeystore(path, pwd, keystore, caInfo.getName().toLowerCase(), caInfo.getCertificateChain().get(0).getEncoded(), null, null);
        final TrustManagerFactory result = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        result.init(keystore);
        return result;
    }
    
    /**
     * Returns a new key manager factory with the keystore stored under the given path. If the keystore does not exists, a new keystore is generated and stored. 
     * 
     * @param path the absolute file path of the keystore.
     * @param pwd the keystore password.
     * @return the key manager factory.
     * 
     * @throws KeyStoreException any.
     * @throws CertificateException any.
     * @throws NoSuchAlgorithmException any.
     * @throws IOException any.
     * @throws UnrecoverableKeyException any.
     */
    public static KeyManagerFactory createKeyManagerFactory(final String path, final String pwd) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        final KeyStore keyStore = WebTestUtils.initJksKeyStore(path, pwd);
        final KeyManagerFactory result = KeyManagerFactory.getInstance("SunX509");
        result.init(keyStore, pwd.toCharArray());
        return result;
    }
    
    /**
     * Returns a new SSL context object for TLSv1.2 using the given trust manager and key manager factories.
     *  
     * @param trustManagerFactory the trust manager factory.
     * @param keyManagerFactory the key manager factory.
     * @return the SSL context object.
     * 
     * @throws NoSuchAlgorithmException any.
     * @throws KeyManagementException any.
     */
    public static SSLContext createSslContext(final TrustManagerFactory trustManagerFactory, final KeyManagerFactory keyManagerFactory) throws NoSuchAlgorithmException, KeyManagementException {
        final SSLContext result = SSLContext.getInstance("TLSv1.2");
        result.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return result;
    }
    
    /**
     * Returns a new end entity information for type {@link EndEntityTypes#ENDUSER} with token type {@link EndEntityConstants#TOKEN_SOFT_P12}.
     * 
     * @param caId the ID of the issuing CA.
     * @param username the name of the end entity
     * @param subjectDN the subjectDN of the end entity.
     * @param pwd the password.
     * 
     * @return the end entity information object.
     */
    public static EndEntityInformation createEndEntityInformation(final int caId, final String username, final String subjectDN, final String pwd) {
        final EndEntityInformation endEntityInformation = new EndEntityInformation(
                username,
                subjectDN,
                caId,
                null,
                null,
                new EndEntityType(EndEntityTypes.ENDUSER),
                1,
                1,
                EndEntityConstants.TOKEN_SOFT_P12,
                null);
        endEntityInformation.setPassword(pwd);
        return endEntityInformation;
    }
    
    /**
     * Binds an end entity certificate to a role by it's subjectDN CN attribute.
     * 
     * @param roleMemberSession the role member session bean.
     * @param token the administrator token.
     * @param username the username of the end entity.
     * @param description the description text of the role binding.
     * @param caId the ID of the CA which has issued the end entity certificate.
     * @param roleId the ID of the role.
     * 
     * @return the role member object.
     * @throws AuthorizationDeniedException if the administrator has insufficient access rules.
     */
    public static RoleMember createRoleMember(final RoleMemberSessionRemote roleMemberSession, final AuthenticationToken token, final String username, final String description, final int caId, final int roleId) throws AuthorizationDeniedException {
        return roleMemberSession.persist( token,
            new RoleMember(
                X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caId,
                RoleMember.NO_PROVIDER,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                username,
                roleId,
                description
            )
        );
    }
    
    /**
     * Issues and stores a client certificate in JSK format.
     * 
     * @param admin the administrator token.
     * @param path the absolute file path of the keystore.
     * @param username the name of the end entity.
     * @param subjectDn the subjectDN.
     * @param pwd the keystore password (= end entity enrollment code).
     * @param caId the ID of the issuing CA.
     * @param caChain the CA chain of the issuing CA.
     * @return the X.509 certificate of the newly generated keystore.
     * 
     * @throws Exception any.
     */
    public static X509Certificate issueAndStoreClientCert(final AuthenticationToken admin, final String path, final String username, final String subjectDn, final String pwd, final int caId, final List<Certificate> caChain) throws Exception {
        final EndEntityManagementSessionRemote eeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        final KeyStore keyStore = initJksKeyStore(path, pwd);
        final EndEntityInformation user = createEndEntityInformation(caId, username, subjectDn, pwd);
        final KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        eeSession.addUser(admin, user, false);
        final SimpleRequestMessage request = new SimpleRequestMessage(keyPair.getPublic(), user.getUsername(), user.getPassword());
        final X509ResponseMessage response = (X509ResponseMessage) signSession.createCertificate(admin, request, X509ResponseMessage.class, user);
        final X509Certificate result = (X509Certificate) response.getCertificate();
        importDataIntoJksKeystore(path, pwd, keyStore, username.toLowerCase(), caChain.get(0).getEncoded(), keyPair, result.getEncoded());
        return result;
    }
    
    /**
     * Encapsulates the HTTP(s) client configuration.
     */
    public static class HttpClientConfig {
        
        AuthenticationToken admin;
        String username;
        String subjectDn;
        String trustStorePath;
        String keyStorePath;
        String trustStorePwd;
        String keyStorePwd;
        TrustManagerFactory trustManagerFactory;
        KeyManagerFactory keyManagerFactory;
        SSLContext sslContext;
        CAInfo serverCaInfo;
        CAInfo clientCaInfo;
        X509Certificate clientCertificate;
        CloseableHttpClient httpClient;
        RoleMember roleMember;
        
        public HttpClientConfig(final AuthenticationToken admin) {
            this.admin = admin;
        } 
                
        public HttpClientConfig build() throws Exception {
            trustManagerFactory = createTrustManagerFactory(trustStorePath, trustStorePwd, serverCaInfo);            
            clientCertificate = issueAndStoreClientCert(admin, keyStorePath, username, subjectDn, keyStorePwd, clientCaInfo.getCAId(), serverCaInfo.getCertificateChain());
            keyManagerFactory = createKeyManagerFactory(keyStorePath, keyStorePwd);
            sslContext = WebTestUtils.createSslContext(trustManagerFactory, keyManagerFactory);
            return this;
        }
        
        public HttpClientConfig withUsername(final String name) {
            this.username = name;
            return this;
        }
        
        public HttpClientConfig withSubjectDn(final String dn) {
            this.subjectDn = dn;
            return this;
        }
        
        public HttpClientConfig withTruststorePath(final String path) {
            this.trustStorePath = path;
            return this;
        }
        
        public HttpClientConfig withTruststorePwd(final String pwd) {
            this.trustStorePwd = pwd;
            return this;
        }
        
        public HttpClientConfig withServerCa(final CAInfo caInfo) {
            this.serverCaInfo = caInfo;
            return this;
        }
        
        public HttpClientConfig withKeystorePath(final String path) {
            this.keyStorePath = path;
            return this;
        }
        
        public HttpClientConfig withKeystorePwd(final String pwd) {
            this.keyStorePwd = pwd;
            return this;
        }
        
        public HttpClientConfig withClientCa(final CAInfo caInfo) {
            this.clientCaInfo = caInfo;
            return this;
        }
        
        public String getUsername() {
            return username;
        }
        public String getSubjectDn() {
            return subjectDn;
        }
        public String getTrustStorePath() {
            return trustStorePath;
        }
        public String getKeyStorePath() {
            return keyStorePath;
        }
        public String getTrustStorePwd() {
            return trustStorePwd;
        }
        public String getKeyStorePwd() {
            return keyStorePwd;
        }
        public TrustManagerFactory getTrustManagerFactory() {
            return trustManagerFactory;
        }
        public KeyManagerFactory getKeyManagerFactory() {
            return keyManagerFactory;
        }
        public SSLContext getSslContext() {
            return sslContext;
        }
        public X509Certificate getClientCertificate() {
            return clientCertificate;
        }
        public CloseableHttpClient getHttpClient() {
            return httpClient;
        }
        public RoleMember getRoleMember() {
            return roleMember;
        }
        public void setRoleMember(final RoleMember roleMember) {
            this.roleMember = roleMember;
        }
        public void setHttpClient(final CloseableHttpClient client) {
            this.httpClient = client;
        }
    }
}

