/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.isNull;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.Role;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.easymock.EasyMock;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.HttpTools;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 */
public final class EjbcaWebBeanImplUnitTest {

    private static final String TEST_ACCESS_RESOURCE = "/test/123";
    private static final byte[] TLS_SESSION_1 = { 11, 11 };
    private static final byte[] TLS_SESSION_2 = { 22, 22 };
    private static final byte[] TLS_SESSION_3 = { 33, 33 };
    private static final String HTTPS = "https";
    private static final String MOCKED_SERVER_NAME = "example.com";
    private static final String MOCKED_REMOTE_ADDR = "192.0.2.123"; // RFC 5737 documentation/example IP address
    
    private static final String CERT_DN = "CN=admin";
    private static final String ISSUER_DN = CERT_DN; // self-signed cert
    private static final String[] BEARER_TOKENS = { "tok111", "tok222" };
    private static final String[] BEARER_TOKEN_FINGERPRINTS = { "fp111", "fp222" };
    private static final OAuth2Principal TEST_CLAIMS = OAuth2Principal.builder().setIssuer("Issuer").setSubject("Subject").setOid("2.999.123").build();
    private static final String OAUTH_PROVIDER_NAME = "OAuth Provider 123";
    private static final List<Role> ADMIN_ROLES = new ArrayList<>(Arrays.asList(new Role(null, "Test Role")));
    
    private static X509Certificate[] allAdminCerts;
    
    private static X509Certificate adminCert;
    private static BigInteger adminSerial;
    private static String adminSerialAsHex;
    private static String adminFingerprint;
    
    private MockedEjbBridgeSession ejbs;
    private EjbcaWebBean ejbcaWebBean;
    private HttpServletRequest mockedRequest;
    private HttpSession mockedSession;
    private List<Object> allMockObjects;
    private ServletContext mockedServletContext;
    private AuthenticationToken mockedAuthToken;
    private OAuthConfiguration dummyOAuthConfig;
    
    private byte[] tlsSession;
    private boolean alreadyInitialized;
    private boolean alreadyFetchedOauthConfig;
    private String bearerToken;
    private String bearerTokenFingerprint;
    
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        final KeyPair kp = KeyTools.genKeys(AlgorithmConstants.SIGALG_ED25519, AlgorithmConstants.KEYALGORITHM_ED25519);
        allAdminCerts = new X509Certificate[2];
        // Serial numbers are randomized, so these certs are random 
        allAdminCerts[0] = CertTools.genSelfCert(CERT_DN, 7, null, kp.getPrivate(), kp.getPublic(), AlgorithmConstants.SIGALG_ED25519, false);
        allAdminCerts[1] = CertTools.genSelfCert(CERT_DN, 7, null, kp.getPrivate(), kp.getPublic(), AlgorithmConstants.SIGALG_ED25519, false);
    }

    @Before
    public void before() {
        allMockObjects = new ArrayList<>();
        ejbs = new MockedEjbBridgeSession();
        ejbcaWebBean = new EjbcaWebBeanImpl(ejbs, null); // skipping enterprise beans here since we don't test enterprise features
        mockedRequest = EasyMock.createStrictMock(HttpServletRequest.class);
        mockedSession = EasyMock.createStrictMock(HttpSession.class);
        mockedServletContext = EasyMock.createStrictMock(ServletContext.class);
        allMockObjects.addAll(ejbs.getAllMockObjects());
        allMockObjects.add(mockedRequest);
        allMockObjects.add(mockedSession);
        allMockObjects.add(mockedServletContext);
        mockedAuthToken = null;
        tlsSession = TLS_SESSION_1;
        alreadyInitialized = false;
        alreadyFetchedOauthConfig = false;
        setClientCertNumber(1);
        setBearerTokenNumber(1);
        dummyOAuthConfig = new OAuthConfiguration();
    }
    
    private static void setClientCertNumber(int number) {
        adminCert = allAdminCerts[number-1];
        adminSerial = CertTools.getSerialNumber(adminCert);
        adminSerialAsHex = CertTools.getSerialNumberAsString(adminCert);
        adminFingerprint = CertTools.getFingerprintAsString(adminCert);
    }
    
    private void setBearerTokenNumber(int number) {
        bearerToken = BEARER_TOKENS[number-1];
        bearerTokenFingerprint = BEARER_TOKEN_FINGERPRINTS[number-1];
    }

    private void replayAll() {
        replay(allMockObjects.toArray());
    }
    
    private void verifyAll() {
        verify(allMockObjects.toArray());
    }
    
    private void resetAll() {
        reset(allMockObjects.toArray());
        allMockObjects.remove(mockedAuthToken);
        mockedAuthToken = null;
    }
    
    private void expectRequestGetters() {
        expect(mockedRequest.getScheme()).andReturn(HTTPS);
        expect(mockedRequest.getServerName()).andReturn(MOCKED_SERVER_NAME);
        expect(mockedRequest.getRemoteAddr()).andReturn(MOCKED_REMOTE_ADDR);
    }
    
    private void expectExtractCertificate() {
        expect(mockedRequest.getAttribute("javax.servlet.request.X509Certificate")).andReturn(new X509Certificate[] { adminCert });
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session_id")).andReturn(tlsSession);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session")).andReturn(null);
        expect(mockedRequest.getHeader(HttpTools.AUTHORIZATION_HEADER)).andReturn(null);
        expect(mockedRequest.getSession(true)).andReturn(mockedSession);
        expect(mockedSession.getAttribute("ejbca.bearer.token")).andReturn(null);
    }
    
    private void expectExtractBearerToken() {
        expect(mockedRequest.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session_id")).andReturn(tlsSession);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session")).andReturn(null);
        expect(mockedRequest.getHeader(HttpTools.AUTHORIZATION_HEADER)).andReturn(null);
        expect(mockedRequest.getSession(true)).andReturn(mockedSession);
        expect(mockedSession.getAttribute("ejbca.bearer.token")).andReturn(bearerToken);
    }
    
    @SuppressWarnings("unchecked")
    private void expectCertAuthWithoutRole() {
        mockedAuthToken = EasyMock.createStrictMock(X509CertificateAuthenticationToken.class);
        allMockObjects.add(mockedAuthToken);
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingClientCertificate(same(adminCert))).andReturn((X509CertificateAuthenticationToken) mockedAuthToken);
        expect(ejbs.getEndEntityManagementSession().checkIfCertificateBelongToUser(adminSerial, ISSUER_DN)).andReturn(true);
        expect(ejbs.getCertificateStoreSession().findCertificateByIssuerAndSerno(ISSUER_DN, adminSerial)).andReturn(adminCert);
        expect(ejbs.getRoleSession().getRolesAuthenticationTokenIsMemberOf(mockedAuthToken)).andReturn(Collections.emptyList());
        ejbs.getSecurityEventsLoggerSession().log(same(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN), same(EventStatus.FAILURE), same(EjbcaModuleTypes.ADMINWEB), 
                same(EjbcaServiceTypes.EJBCA), anyString(), anyString(), eq(adminSerialAsHex), isNull(), (Map<String,Object>)anyObject());
        expectLastCall();
    }
    
    @SuppressWarnings("unchecked")
    private void expectSuccessfulClientCertAuth() {
        final X509CertificateAuthenticationToken certToken = EasyMock.createStrictMock(X509CertificateAuthenticationToken.class);
        allMockObjects.add(certToken);
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingClientCertificate(same(adminCert))).andReturn(certToken);
        expect(ejbs.getEndEntityManagementSession().checkIfCertificateBelongToUser(adminSerial, ISSUER_DN)).andReturn(true);
        expect(ejbs.getCertificateStoreSession().findCertificateByIssuerAndSerno(ISSUER_DN, adminSerial)).andReturn(adminCert);
        expect(ejbs.getRoleSession().getRolesAuthenticationTokenIsMemberOf(certToken)).andReturn(ADMIN_ROLES);
        ejbs.getSecurityEventsLoggerSession().log(same(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN), same(EventStatus.SUCCESS), same(EjbcaModuleTypes.ADMINWEB), 
                same(EjbcaServiceTypes.EJBCA), anyString(), anyString(), eq(adminSerialAsHex), isNull(), (Map<String,Object>)anyObject());
        expectLastCall();
        mockedAuthToken = certToken;
    }
    
    @SuppressWarnings("unchecked")
    private void expectSuccessfulBearerTokenAuth() throws TokenExpiredException {
        final OAuth2AuthenticationToken oauthToken = EasyMock.createStrictMock(OAuth2AuthenticationToken.class);
        allMockObjects.add(oauthToken);
        expect(oauthToken.getClaims()).andReturn(TEST_CLAIMS);
        expect(oauthToken.getPublicKeyBase64Fingerprint()).andReturn(bearerTokenFingerprint);
        if (!alreadyFetchedOauthConfig) {
            expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID)).andReturn(dummyOAuthConfig);
            alreadyFetchedOauthConfig = true;
        }
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingOAuthBearerToken(same(dummyOAuthConfig), eq(bearerToken))).andReturn(oauthToken);
        expect(oauthToken.getProviderLabel()).andReturn(OAUTH_PROVIDER_NAME).anyTimes();
        expect(ejbs.getRoleSession().getRolesAuthenticationTokenIsMemberOf(oauthToken)).andReturn(ADMIN_ROLES);
        ejbs.getSecurityEventsLoggerSession().log(same(EjbcaEventTypes.ADMINWEB_ADMINISTRATORLOGGEDIN), same(EventStatus.SUCCESS), same(EjbcaModuleTypes.ADMINWEB), 
                same(EjbcaServiceTypes.EJBCA), anyString(), anyString(), eq("Subject"), isNull(), (Map<String,Object>)anyObject());
        expectLastCall();
        mockedAuthToken = oauthToken;
    }
    
    /** Common initialization. Done for both successful and failed authentication */
    private void expectCommonInitialization() {
        expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).andReturn(new GlobalConfiguration());
        expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID)).andReturn(new CmpConfiguration());
        expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID)).andReturn(new AvailableExtendedKeyUsagesConfiguration());
        expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID)).andReturn(new AvailableCustomCertificateExtensionsConfiguration());
        expect(mockedRequest.getSession(true)).andReturn(mockedSession);
        expect(mockedSession.getServletContext()).andReturn(mockedServletContext); // currently not required
    }

    /** Initialization on successful authentication */
    private void expectSuccessfulAuthInitialization(boolean authorized) {
        expectCommonInitialization();
        expect(ejbs.getAuthorizationSession().isAuthorized(same(mockedAuthToken), eq(TEST_ACCESS_RESOURCE))).andReturn(authorized);
        if (authorized && !alreadyInitialized) {
            expect(ejbs.getAdminPreferenceSession().getAdminPreference(same(mockedAuthToken))).andReturn(new AdminPreference());
            // Return empty language files. We don't need them in this test
            expect(mockedServletContext.getResourceAsStream(anyString())).andReturn(new ByteArrayInputStream(new byte[0])).anyTimes();
        } else if (!authorized) {
            expectErrorPageInitiaization(false);
        }
    }
    
    /** Initialization on failed authentication */
    private void expectErrorPageInitiaization(final boolean expectGetIp) {
        if (expectGetIp) {
            expect(mockedRequest.getRemoteAddr()).andReturn(MOCKED_REMOTE_ADDR); // for PublicAuthenticationToken
        }
        expectCommonInitialization();
        expect(ejbs.getAdminPreferenceSession().getDefaultAdminPreference()).andReturn(new AdminPreference());
        expect(mockedServletContext.getResourceAsStream(anyString())).andReturn(new ByteArrayInputStream(new byte[0])).anyTimes();
    }

    
    @Test
    public void noToken() throws Exception {
        expect(mockedRequest.getAttribute("javax.servlet.request.X509Certificate")).andReturn(null);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session_id")).andReturn(tlsSession);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session")).andReturn(null);
        expect(mockedRequest.getHeader(HttpTools.AUTHORIZATION_HEADER)).andReturn(null);
        expect(mockedRequest.getSession(true)).andReturn(mockedSession);
        expect(mockedSession.getAttribute("ejbca.bearer.token")).andReturn(null);
        expectRequestGetters();
        expectErrorPageInitiaization(true);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthenticationFailedException e) { // Expected
            assertEquals("Client certificate or OAuth bearer token required.", e.getMessage());
        }
        verifyAll();
        assertTrue("Authentication token should be PublicAccessAuthenticationToken", ejbcaWebBean.getAdminObject() instanceof PublicAccessAuthenticationToken);
    }

    @Test
    public void unknownCert() throws Exception {
        expectExtractCertificate();
        expectRequestGetters();
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingClientCertificate(same(adminCert))).andReturn(null);
        expectErrorPageInitiaization(true);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthenticationFailedException e) { // Expected
            assertEquals("Authentication failed for certificate: CN=admin", e.getMessage());
        }
        verifyAll();
        assertTrue("Authentication token should be PublicAccessAuthenticationToken", ejbcaWebBean.getAdminObject() instanceof PublicAccessAuthenticationToken);
    }
    
    @Test
    public void unknownBearerToken() throws Exception {
        expectExtractBearerToken();
        expectRequestGetters();
        expect(ejbs.getGlobalConfigurationSession().getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID)).andReturn(dummyOAuthConfig);
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingOAuthBearerToken(same(dummyOAuthConfig), eq(bearerToken))).andReturn(null);
        expectErrorPageInitiaization(true);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthenticationFailedException e) { // Expected
            assertEquals("Authentication failed using OAuth Bearer Token", e.getMessage());
        }
        verifyAll();
        assertTrue("Authentication token should be PublicAccessAuthenticationToken", ejbcaWebBean.getAdminObject() instanceof PublicAccessAuthenticationToken);
    }
    
    @Test
    public void clientCertWithoutEndEntity() throws Exception {
        expectExtractCertificate();
        expectRequestGetters();
        mockedAuthToken = EasyMock.createStrictMock(X509CertificateAuthenticationToken.class);
        allMockObjects.add(mockedAuthToken);
        expect(ejbs.getWebAuthenticationProviderSession().authenticateUsingClientCertificate(same(adminCert))).andReturn((X509CertificateAuthenticationToken) mockedAuthToken);
        expect(ejbs.getEndEntityManagementSession().checkIfCertificateBelongToUser(adminSerial, ISSUER_DN)).andReturn(false);
        expectErrorPageInitiaization(false);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthenticationFailedException e) { // Expected
            assertTrue("Wrong exception message.", e.getMessage().contains("did not belong to any user in the database"));
        }
        verifyAll();
    }
    
    @Test
    public void clientCertWithoutRole() throws Exception {
        expectExtractCertificate();
        expectRequestGetters();
        expectCertAuthWithoutRole();
        expectErrorPageInitiaization(false);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthenticationFailedException e) { // Expected
            assertEquals("Authentication failed for certificate with no access: " + CERT_DN, e.getMessage());
        }
        verifyAll();
        assertEquals("Admin should have an authentication token (but without access)", mockedAuthToken, ejbcaWebBean.getAdminObject());
    }

    @Test
    public void notAuthorized() throws Exception {
        expectExtractCertificate();
        expectRequestGetters();
        expectSuccessfulClientCertAuth();
        expectSuccessfulAuthInitialization(false);
        replayAll();
        try {
            ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
            fail("Should fail");
        } catch (AuthorizationDeniedException e) { // Expected
            assertEquals("You are not authorized to view this page.", e.getMessage());
        }
        verifyAll();
        assertEquals("Admin should have an authentication token (but without access)", mockedAuthToken, ejbcaWebBean.getAdminObject());
    }

    /** Tests successful authentication with client certificate, no OAuth2 token */
    @Test
    public void clientCert() throws Exception {
        expectExtractCertificate();
        expectRequestGetters();
        expectSuccessfulClientCertAuth();
        expectSuccessfulAuthInitialization(true);
        replayAll();
        ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
        verifyAll();
        assertEquals("Wrong admin fingerprint", adminFingerprint, ejbcaWebBean.getCertificateFingerprint());
        assertEquals("Admin should have an authentication token", mockedAuthToken, ejbcaWebBean.getAdminObject());
    }

    /** Tests successful authentication without client certificate but with OAuth2 token */
    @Test
    public void bearerToken() throws Exception {
        expectExtractBearerToken();
        expectRequestGetters();
        expectSuccessfulBearerTokenAuth();
        expectSuccessfulAuthInitialization(true);
        replayAll();
        ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
        verifyAll();
        assertNull("Certificate fingerprint should be null", ejbcaWebBean.getCertificateFingerprint());
        assertEquals("Admin should have an authentication token", mockedAuthToken, ejbcaWebBean.getAdminObject());
    }
    
    @Test
    public void certWithoutRoleButAuthorizedBearerToken() throws Exception {
        expect(mockedRequest.getAttribute("javax.servlet.request.X509Certificate")).andReturn(new X509Certificate[] { adminCert });
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session_id")).andReturn(tlsSession);
        expect(mockedRequest.getAttribute("javax.servlet.request.ssl_session")).andReturn(null);
        expect(mockedRequest.getHeader(HttpTools.AUTHORIZATION_HEADER)).andReturn(null);
        expect(mockedRequest.getSession(true)).andReturn(mockedSession);
        expect(mockedSession.getAttribute("ejbca.bearer.token")).andReturn(bearerToken);
        expectRequestGetters();
        // First, EJBCA tries to authenticate with client cert 
        expectCertAuthWithoutRole();
        // Then with OAuth2
        expectSuccessfulBearerTokenAuth();
        expectSuccessfulAuthInitialization(true);
        replayAll();
        ejbcaWebBean.initialize(mockedRequest, TEST_ACCESS_RESOURCE);
        verifyAll();
        assertNull("Certificate fingerprint should be null", ejbcaWebBean.getCertificateFingerprint());
        assertEquals("Admin should have an authentication token", mockedAuthToken, ejbcaWebBean.getAdminObject());
    }
    
    /**
     * Checks that authentication is cached when the session, TLS session and fingerprint stays the same.
     */
    @Test
    public void clientCertAuthenticationCache() throws Exception {
        clientCert();
        resetAll(); // restart EasyMock state
        expectExtractCertificate();
        // authentication is cached here, and we skip to the authorization check
        expect(ejbs.getAuthorizationSession().isAuthorized(same(mockedAuthToken), eq(TEST_ACCESS_RESOURCE))).andReturn(true);
    }
    
    @Test
    public void bearerTokenAuthenticationCache() throws Exception {
        bearerToken();
        resetAll();
        expectExtractBearerToken();
        // authentication is cached here, and we skip to the authorization check
        expect(ejbs.getAuthorizationSession().isAuthorized(same(mockedAuthToken), eq(TEST_ACCESS_RESOURCE))).andReturn(true);
    }
    
    /**
     * Tests two authentications with the same JSF session, but with different TLS
     * sessions. This should trigger a re-authentication.
     */
    @Test
    public void clientCertTlsSessionChange() throws Exception {
        clientCert();
        resetAll();
        tlsSession = TLS_SESSION_2;
        clientCert(); // should perform authentication again
    }

    @Test
    public void bearerTokenTlsSessionChange() throws Exception {
        bearerToken();
        resetAll();
        tlsSession = TLS_SESSION_2;
        bearerToken(); // should perform authentication again
    }
    
    @Test
    public void bothTlsSessionChange() throws Exception {
        certWithoutRoleButAuthorizedBearerToken();
        resetAll();
        tlsSession = TLS_SESSION_2;
        certWithoutRoleButAuthorizedBearerToken(); // should perform authentication again
    }
    
    @Test
    public void tlsSessionChangeWithAuthMethodChange() throws Exception {
        certWithoutRoleButAuthorizedBearerToken();
        resetAll();
        tlsSession = TLS_SESSION_2;
        clientCert(); // should perform authentication again
        resetAll();
        tlsSession = TLS_SESSION_3;
        clientCert(); // should also perform authentication again
    }
    
    /**
     * Tests fingerprint change without TLS session change.
     * This can happen when there is a reverse proxy in front of EJBCA with a persistent connection.
     * If there is a new client connection, then the proxy can still use the same TLS connection to EJBCA
     * so the fingerprint of the cert/token needs to verified. 
     */
    @Test
    public void clientCertFingerprintChange() throws Exception {
        clientCert();
        resetAll();
        setClientCertNumber(2);
        clientCert(); // should perform authentication again
    }
    
    @Test
    public void bearerTokenFingerprintChange() throws Exception {
        bearerToken();
        resetAll();
        setBearerTokenNumber(2);
        bearerToken(); // should perform authentication again
    }
    
    @Test
    public void bothTokenFingerprintChange() throws Exception {
        certWithoutRoleButAuthorizedBearerToken();
        resetAll();
        setBearerTokenNumber(2);
        certWithoutRoleButAuthorizedBearerToken(); // should perform authentication again
    }
}
