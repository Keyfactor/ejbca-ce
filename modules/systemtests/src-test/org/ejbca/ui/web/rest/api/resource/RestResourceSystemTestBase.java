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
package org.ejbca.ui.web.rest.api.resource;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionProxyRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.rest.api.config.ObjectMapperContextResolver;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient43Engine;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * An intermediate class to support REST API system tests and setup the SSL connection/authentication.
 */
public class RestResourceSystemTestBase {

    private static final Logger log = Logger.getLogger(RestResourceSystemTestBase.class);
    // Shared EJB instances
    protected static final ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    protected static final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    protected static final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    protected static final ApprovalSessionProxyRemote approvalProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionProxyRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    protected static final CryptoTokenManagementSessionRemote cryptoTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    protected static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    protected static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    protected static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    protected static final KeyStoreCreateSessionRemote keyStoreCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    protected static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    protected static final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    protected static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    protected static final EndEntityAuthenticationSessionRemote endEntityAuthenticationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAuthenticationSessionRemote.class);
    protected static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    //
    protected static final ObjectMapperContextResolver objectMapperContextResolver = new ObjectMapperContextResolver();
    //
    private static final ConfigurationSessionRemote CONFIGURATION_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    //
    private static final String HTTPS_HOST = SystemTestsConfiguration.getRemoteHost(CONFIGURATION_SESSION.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
    private static final String HTTPS_PORT = SystemTestsConfiguration.getRemotePortHttps(CONFIGURATION_SESSION.getProperty(WebConfiguration.CONFIG_HTTPSSERVERPRIVHTTPS));
    //
    private static final String KEY_STORE_PASSWORD = "changeit";
    private static final String TRUSTED_STORE_PATH = System.getProperty("java.io.tmpdir") + File.separator + "truststore_" + new Date().getTime() + ".jks";
    private static final String CERTIFICATE_USER_NAME = "RestApiTestUser";
    private static final String CERTIFICATE_SUBJECT_DN = "CN=" + CERTIFICATE_USER_NAME;
    private static final String CERTIFICATE_USER_NAME_NOADMIN = "RestApiTestUserNoAdmin";
    private static final String CERTIFICATE_SUBJECT_DN_NOADMIN = "CN=" + CERTIFICATE_USER_NAME_NOADMIN;
    private static final String CERTIFICATE_PASSWORD = "RestApiTestUser123";
    private static final X509Certificate X_509_CERTIFICATE;
    private static final X509Certificate X_509_CERTIFICATE_NOADMIN;
    private static final String LOGIN_STORE_PATH = System.getProperty("java.io.tmpdir") + File.separator + "restapitestuser_" + new Date().getTime() + ".jks";
    private static final String LOGIN_STORE_PATH_NOADMIN = System.getProperty("java.io.tmpdir") + File.separator + "restapitestuser_noadmin_" + new Date().getTime() + ".jks";
    private static final String SUPER_ADMINISTRATOR_ROLE_NAME = "Super Administrator Role";
    private static final RoleMember ROLE_MEMBER;
    private static final KeyStore ADMIN_KEYSTORE;
    private static final KeyStore NOADMIN_KEYSTORE;
    private static final KeyStore TRUST_KEYSTORE;
    private static AvailableProtocolsConfiguration protocolConfigBackup;
    
    protected static final AuthenticationToken INTERNAL_ADMIN_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaRestApiTest"));
    
    protected static final int HTTP_STATUS_CODE_UNPROCESSABLE_ENTITY = 422;
    protected static final int HTTP_STATUS_CODE_BAD_REQUEST = 400;    
    protected static final int HTTP_STATUS_CODE_OK = 200;
    protected static final int HTTP_STATUS_CODE_ACCEPTED = 202;

    static {
        clearLoginCertificateSetup(); // Always make sure we start with a clean environment
        try {
            // Trusted CA setup: import CA that issued server certificate into trustedKeyStore (configurable with target.servercert.ca)
            final CAInfo serverCertCaInfo = CaTestUtils.getServerCertCaInfo(INTERNAL_ADMIN_TOKEN);
            final CAInfo clientCertCaInfo = CaTestUtils.getClientCertCaInfo(INTERNAL_ADMIN_TOKEN);
            final List<Certificate> trustedCaCertificateChain = serverCertCaInfo.getCertificateChain();
            TRUST_KEYSTORE = initJksKeyStore(TRUSTED_STORE_PATH);
            importDataIntoJksKeystore(TRUSTED_STORE_PATH, TRUST_KEYSTORE, serverCertCaInfo.getName().toLowerCase(), trustedCaCertificateChain.get(0).getEncoded(), null, null);
            // Login Certificate setup:
            // - - Import trusted CA (configurable with target.clientcert.ca) into loginKeyStore
            // - Sign a certificate using this CA
            // - RestApiTestUser certificate and private key import into loginKeyStore
            // admin
            ADMIN_KEYSTORE = initJksKeyStore(LOGIN_STORE_PATH);
            final EndEntityInformation endEntityInformation = createEndEntityInformation(CERTIFICATE_USER_NAME, CERTIFICATE_SUBJECT_DN, clientCertCaInfo.getCAId());
            KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, endEntityInformation, false);
            SimpleRequestMessage simpleRequestMessage = new SimpleRequestMessage(keyPair.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
            final X509ResponseMessage x509ResponseMessage = (X509ResponseMessage) signSession.createCertificate(INTERNAL_ADMIN_TOKEN, simpleRequestMessage, X509ResponseMessage.class, endEntityInformation);
            X_509_CERTIFICATE = (X509Certificate) x509ResponseMessage.getCertificate();
            final Role role = roleSession.getRole(INTERNAL_ADMIN_TOKEN, null, SUPER_ADMINISTRATOR_ROLE_NAME);
            ROLE_MEMBER = roleMemberSession.persist(INTERNAL_ADMIN_TOKEN,
                    new RoleMember(
                            X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                            clientCertCaInfo.getCAId(), RoleMember.NO_PROVIDER,
                            X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                            AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                            CERTIFICATE_USER_NAME,
                            role.getRoleId(),
                            CERTIFICATE_USER_NAME + " for REST API Tests"
                    )
            );
            importDataIntoJksKeystore(LOGIN_STORE_PATH, ADMIN_KEYSTORE, CERTIFICATE_USER_NAME.toLowerCase(), trustedCaCertificateChain.get(0).getEncoded(), keyPair, X_509_CERTIFICATE.getEncoded());

            // noadmin
            NOADMIN_KEYSTORE = initJksKeyStore(LOGIN_STORE_PATH_NOADMIN);
            final EndEntityInformation endEntityInformationNoAdmin = createEndEntityInformation(CERTIFICATE_USER_NAME_NOADMIN, CERTIFICATE_SUBJECT_DN_NOADMIN, clientCertCaInfo.getCAId());
            keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            endEntityManagementSession.addUser(INTERNAL_ADMIN_TOKEN, endEntityInformationNoAdmin, false);
            simpleRequestMessage = new SimpleRequestMessage(keyPair.getPublic(), endEntityInformationNoAdmin.getUsername(), endEntityInformationNoAdmin.getPassword());
            final X509ResponseMessage x509ResponseMessageNoAdmin = (X509ResponseMessage) signSession.createCertificate(INTERNAL_ADMIN_TOKEN, simpleRequestMessage, X509ResponseMessage.class, endEntityInformationNoAdmin);
            X_509_CERTIFICATE_NOADMIN = (X509Certificate) x509ResponseMessageNoAdmin.getCertificate();
            importDataIntoJksKeystore(LOGIN_STORE_PATH_NOADMIN, NOADMIN_KEYSTORE, CERTIFICATE_USER_NAME_NOADMIN.toLowerCase(), trustedCaCertificateChain.get(0).getEncoded(), keyPair, X_509_CERTIFICATE_NOADMIN.getEncoded());
        } catch (AuthorizationDeniedException | CertificateException | NoSuchAlgorithmException | IOException |
                KeyStoreException | InvalidAlgorithmParameterException |
                CertificateSerialNumberException | EndEntityExistsException | CADoesntExistsException |
                WaitingForApprovalException | EndEntityProfileValidationException | ApprovalException |
                IllegalNameException | CustomFieldException | InvalidAlgorithmException | CustomCertificateSerialNumberException |
                AuthLoginException | NoSuchEndEntityException | CertificateExtensionException | CertificateRevokeException |
                IllegalValidityException | AuthStatusException | CryptoTokenOfflineException | SignRequestSignatureException |
                CertificateCreateException | SignRequestException | IllegalKeyException | CAOfflineException e) {
            // Remove any artifacts from the database
            clearLoginCertificateSetup();
            throw new RuntimeException("Cannot setup a HttpClient with SSL connection.", e);
        }
    }

    public static void beforeClass() throws Exception {
        backupProtocolConfiguration();
        enableRestProtocolConfiguration();
    }

    protected static void setMaxSearchResults(int maxResults) throws Exception {
        GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration)
                 globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        globalCesecoreConfiguration.setMaximumQueryCount(maxResults);
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, globalCesecoreConfiguration);
    }
    
    protected static void enableRestProtocolConfiguration() throws AuthorizationDeniedException {
        AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration) 
                globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CA_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_COAP_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CRYPTOTOKEN_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT_V2.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_ENDENTITY_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_ENDENTITY_MANAGEMENT_V2.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CONFIGDUMP.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_SSH_V1.getName(), true);
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, availableProtocolsConfiguration);
    }
    
    protected static void disableRestProtocolConfiguration() throws AuthorizationDeniedException {
        AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration) 
                globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CA_MANAGEMENT.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_COAP_MANAGEMENT.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CRYPTOTOKEN_MANAGEMENT.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT_V2.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_ENDENTITY_MANAGEMENT.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_ENDENTITY_MANAGEMENT_V2.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CONFIGDUMP.getName(), false);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_SSH_V1.getName(), false);
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, availableProtocolsConfiguration);
    }
    
    protected static void backupProtocolConfiguration() {
        protocolConfigBackup = (AvailableProtocolsConfiguration) 
                globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }

    protected static void restoreProtocolConfiguration() throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(INTERNAL_ADMIN_TOKEN, protocolConfigBackup);
    }
    
    public static void afterClass() throws Exception {
        clearLoginCertificateSetup();
        // Remove keystores
        final File trustedStore = new File(TRUSTED_STORE_PATH);
        if(trustedStore.exists()) {
            trustedStore.delete();
        }
        final File loginStore = new File(LOGIN_STORE_PATH);
        if(loginStore.exists()) {
            loginStore.delete();
        }
        restoreProtocolConfiguration();
    }

    /**
     * Forms a REST API request denoted by URI.
     * <br/>
     * For example newRequest("/v1/ca") forms the request on URL "https://localhost:8443/ejbca/ejbca-rest-api/v1/ca".
     *
     * @param uriPath a part of URL to make request on.
     *
     * @return An instance of WebTarget.
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * @throws KeyManagementException 
     *
     * @see org.jboss.resteasy.client.ClientRequest
     */
    static WebTarget newRequest(final String uriPath) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        ApacheHttpClient43Engine engine = new ApacheHttpClient43Engine(getHttpClient(true));
        ResteasyClientBuilder builder = (ResteasyClientBuilder)ClientBuilder.newBuilder();
        Client newClient = builder.httpEngine(engine).build();
        return newClient.target(getBaseUrl() + uriPath);
    }

    WebTarget newRequestNoAdmin(final String uriPath) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
        ApacheHttpClient43Engine engine = new ApacheHttpClient43Engine(getHttpClient(false));
        ResteasyClientBuilder builder = (ResteasyClientBuilder)ClientBuilder.newBuilder();
        Client newClient = builder.httpEngine(engine).build();
        WebTarget webTarget = newClient.target(getBaseUrl() +uriPath);
        return webTarget;
    }

    static HttpClient getHttpClient(boolean isAdmin) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException{
        // Setup the SSL Context using prepared trustedKeyStore and loginKeyStore
        final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(TRUST_KEYSTORE);
        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(isAdmin ? ADMIN_KEYSTORE : NOADMIN_KEYSTORE, KEY_STORE_PASSWORD.toCharArray());
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(new NoopHostnameVerifier())
                .build();
        return client;
    }

    public static String getBaseUrl() {
        return "https://"+ HTTPS_HOST +":" + HTTPS_PORT + "/ejbca/ejbca-rest-api";
    }

    private static KeyStore initJksKeyStore(final String keyStoreFilePath) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final File file = new File(keyStoreFilePath);
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        if (file.exists()) {
            keyStore.load(new FileInputStream(file), KEY_STORE_PASSWORD.toCharArray());
        } else {
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), KEY_STORE_PASSWORD.toCharArray());
        }
        return keyStore;
    }

    private static void importDataIntoJksKeystore(
            final String keyStoreFilePath,
            final KeyStore keyStore,
            final String keyStoreAlias,
            final byte[] issuerCertificateBytes,
            final KeyPair keyPair,
            final byte[] certificateBytes
    ) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        // Add the certificate
        keyStore.setCertificateEntry(keyStoreAlias, getCertificateFromBytes(issuerCertificateBytes));
        // Add the key if exists
        if(keyPair != null) {
            final Certificate[] chain = { getCertificateFromBytes(certificateBytes) };
            keyStore.setKeyEntry(keyStoreAlias, keyPair.getPrivate(), KEY_STORE_PASSWORD.toCharArray(), chain);
        }
        // Save the new keystore contents
        final FileOutputStream fileOutputStream = new FileOutputStream(keyStoreFilePath);
        keyStore.store(fileOutputStream, KEY_STORE_PASSWORD.toCharArray());
        fileOutputStream.close();
    }

    protected static void setupClientKeyStore(final CAInfo serverCertCaInfo, final KeyPair clientKeys, final X509Certificate clientCert)
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    final List<Certificate> trustedCaCertificateChain = serverCertCaInfo.getCertificateChain();
        KeyStore clientKeyStore = initJksKeyStore(LOGIN_STORE_PATH);
    importDataIntoJksKeystore(LOGIN_STORE_PATH, clientKeyStore, CertTools.getPartFromDN(CertTools.getSubjectDN(clientCert), "CN"),
            trustedCaCertificateChain.get(0).getEncoded(), clientKeys, clientCert.getEncoded());
}

    private static Certificate getCertificateFromBytes(final byte[] certificateBytes) throws CertificateException {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final InputStream certificateInputStream = new ByteArrayInputStream(certificateBytes);
        return certificateFactory.generateCertificate(certificateInputStream);
    }

    private static EndEntityInformation createEndEntityInformation(final String username, final String subjectDN, final int caId) {
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
        endEntityInformation.setPassword(CERTIFICATE_PASSWORD);
        return endEntityInformation;
    }

    private static void clearLoginCertificateSetup() {
        // Remove the end entity if exists
        if (endEntityManagementSession.existsUser(CERTIFICATE_USER_NAME)) {
            try {
                endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, CERTIFICATE_USER_NAME);
            }
            catch (AuthorizationDeniedException | NoSuchEndEntityException | CouldNotRemoveEndEntityException e) {
                log.error("Cannot remove the user [" + CERTIFICATE_USER_NAME + "]", e);
            }
        }
        if (endEntityManagementSession.existsUser(CERTIFICATE_USER_NAME_NOADMIN)) {
            try {
                endEntityManagementSession.deleteUser(INTERNAL_ADMIN_TOKEN, CERTIFICATE_USER_NAME_NOADMIN);
            }
            catch (AuthorizationDeniedException | NoSuchEndEntityException | CouldNotRemoveEndEntityException e) {
                log.error("Cannot remove the user [" + CERTIFICATE_USER_NAME_NOADMIN + "]", e);
            }
        }
        // Remove the certificates if exists
        if(X_509_CERTIFICATE != null) {
            internalCertificateStoreSession.removeCertificate(X_509_CERTIFICATE);
        }
        if(X_509_CERTIFICATE_NOADMIN != null) {
            internalCertificateStoreSession.removeCertificate(X_509_CERTIFICATE_NOADMIN);
        }
        // Remove the membership
        if(ROLE_MEMBER != null) {
            try {
                roleMemberSession.remove(INTERNAL_ADMIN_TOKEN, ROLE_MEMBER.getId());
            }
            catch (AuthorizationDeniedException e) {
                log.error("Cannot remove the membership", e);
            }
        }
    }
    
    public String encodeUrl(String path) {
        try {
            path = URLEncoder.encode(path, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            log.error("Error encoding parameter: " + e.getMessage());
        }
        return path;
    }

}
