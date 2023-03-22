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

package org.ejbca.ui.web.pub;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.OAuth2AccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeProxySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import static org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols.RA_WEB;
import static org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols.REST_CERTIFICATE_MANAGEMENT;
import static org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols.WS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;


/**
 * Tests http requests with bearer token (oauth)
 */
public class OAuthSystemTest {

    private static final String AZURE_AUDIENCE = "api://f4b51ae1-77e0-4367-be11-5a43b6b20358";
    private static final String OAUTH_SUB = "OauthSystemTestSub";
    private static final String CA = "OauthSystemTestCA";
    private static final String OAUTH_KEY = "OauthSystemTestKey";
    private static final String ROLENAME = "OauthSystemTestRole";
    protected static final String PASSWORD = "foo123";

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyiRvfMhXb1nLE+bQ8Dtg\n" +
            "P/YFPm6nesE+hNeSlxXQbdRI/Vd6djyynnptBVxZIvRmuax/zQRNqdK+FsoZKQGJ\n" +
            "978PuBhFoLsgCyccrqCEfO2kZp9atXFYoctgXW339Kj2bF5zRhYlSqCD/vBKcjCd\n" +
            "d6q0myEseplcPUzZXWbKHsdP4irjNRS3SwjKjetDBZ6FquAb5jXlSFH9JUx8iRYF\n" +
            "Bv4F3TDWC1NHFp3fpLovUjcZama6nrY7VQfnsLFY2YKPahQqikd4NSny2wmnonnw\n" +
            "Vyos88Ylt//DlzVgijMOvDE4TKF81g4qbd7x8B/JpPxdBk3gXdgJk8+S+scOqfPX\n" +
            "swIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEAyiRvfMhXb1nLE+bQ8DtgP/YFPm6nesE+hNeSlxXQbdRI/Vd6\n" +
            "djyynnptBVxZIvRmuax/zQRNqdK+FsoZKQGJ978PuBhFoLsgCyccrqCEfO2kZp9a\n" +
            "tXFYoctgXW339Kj2bF5zRhYlSqCD/vBKcjCdd6q0myEseplcPUzZXWbKHsdP4irj\n" +
            "NRS3SwjKjetDBZ6FquAb5jXlSFH9JUx8iRYFBv4F3TDWC1NHFp3fpLovUjcZama6\n" +
            "nrY7VQfnsLFY2YKPahQqikd4NSny2wmnonnwVyos88Ylt//DlzVgijMOvDE4TKF8\n" +
            "1g4qbd7x8B/JpPxdBk3gXdgJk8+S+scOqfPXswIDAQABAoIBAQCeUCDcqo8Hz1xj\n" +
            "7s7OhsIf9c8vkTwrwLL1GVxeZaBClBLCD0QC3BDMW3eMzkGlRaI6YqYI7AjjKwDj\n" +
            "Gk7QNbtXQ9TMyn2ln0g+U9h7z41Txk6ObNl+5xGSTZTgN2MNw1KTlvlS978nDkWy\n" +
            "YYD8o6R/9zrRkA6kyf1aqRhHtVww82WFbB5DV5yqIxz8wLU7ugzs/2iiV/aqq5cJ\n" +
            "WRHFhiqmtA+88fAdrCTq0DWif6Chf5SYrY2pirTBHFpqVWs/3cq86eoVFpMYlMCY\n" +
            "AxroxHjLmJM0sSB6wCDfJEMgBtMgIm6Boh4xSM6KcOZitcj51dvM3Deh5BhJnNdq\n" +
            "oAtod/ThAoGBAO+9vXFYUBa9Yn+d1PBXc4X0iNMEh7jdGdqD6QRrBOwb2sYEishz\n" +
            "kaIZSM0U8yoApS5vDxGTYSdUm53rX5/d4tfW2BNjomV2dD6u3RyhXBz84aSHeWX8\n" +
            "p02ZzDjHUxR7CZ2ZmbsN1Ite+AKb/zwDt5KaiVSCyNwlhxwKJ454PecDAoGBANfZ\n" +
            "7JN07SBtaSD6Q3N7V7WvhrQzm/GU477+LYhLWtGPp/KylvSKuPK3jL3/cvk+Mm3l\n" +
            "UkCF5sZ3A2fbkymP7koHQPGDqSrKH0qAN4+g5zuy0R6+bKdpqkUVuESLG8YCYfOM\n" +
            "cqhc+JvD4ECYEBNgBsBcwUHLOtu0eSss76bbEFWRAoGAZtj8M2rSeN7oKZ05I54w\n" +
            "pg/gvr4bx3e6xp5+UXHj27KbaQW70ACcQnEcZTaOlr9OHZxxV3XlYO0QEXBPRpL2\n" +
            "5Od7LN46ZdKqTdXQb57dmGX4GxAvSUxZLZZEITuJbajW2DBz3eYx/1RPizcHCOUD\n" +
            "VLZNId81chP7YVEN5TW6QKcCgYEAjeF69foXnAcO4VRfXdsnbg9wVabOzF73zKU6\n" +
            "vKn7imAJHyhwvVEp/LDV3FW690YA0+e2xx688JtuK6hS9TDciuB1ucq3OZ8eLlRV\n" +
            "MR2soLsLZk/5D5oPB9YdB0EBAoiyZepdu3lRGOIJ16ucdX/bMDpH9b1mdOAN/WlO\n" +
            "Jbk85WECgYBMV1RqyFI7eCg5h6F934mU2h/cq9HdYLFX+vvEG+CwYviJF6p5R44u\n" +
            "NAoG0QxYULgcHIscLySYau4lHRgv7hAOrhY+UsJ3MnI97Gea4Gvvu4e5F13fzjlp\n" +
            "GmQnXm8ydcaDNPM6Xp7nMMjNAwXB0H9z9DFKejPFT1aDmnHY+1X+SA==\n" +
            "-----END PRIVATE KEY-----\n";

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("OauthSystemTest"));

    private static GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final EnterpriseEditionEjbBridgeProxySessionRemote enterpriseEjbBridgeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EnterpriseEditionEjbBridgeProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    private static final String HTTP_HOST = SystemTestsConfiguration.getRemoteHost(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
    private static final String HTTP_PORT = SystemTestsConfiguration.getRemotePortHttp(configurationSession.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTPS));
    private static final String HTTP_REQ_PATH = "https://" + HTTP_HOST + ":" + HTTP_PORT + "/ejbca";
    private static String oAuthKeyInfoLabel;
    private static CA adminca;
    private static RoleMember roleMember;
    private static String token;
    private static String expiredToken;
    private static SSLSocketFactory defaultSocketFactory;
    private static boolean isRestEnabled;
    private static boolean isRaWebEnabled;
    private static boolean isWsEnabled;

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();
    @ClassRule
    public static final TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException, InvalidKeySpecException, AuthorizationDeniedException, RoleExistsException, CertificateException, OperatorCreationException, CryptoTokenOfflineException, KeyManagementException, KeyStoreException, IOException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // Public key
        byte[] pubKeyBytes = KeyTools.getBytesFromPEM(PUBLIC_KEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        // Private key
        final PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(KeyTools.getBytesFromPEM(PRIVATE_KEY, CertTools.BEGIN_PRIVATE_KEY, CertTools.END_PRIVATE_KEY));
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = keyFactory.generatePrivate(pkKeySpec);

        OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        oAuthConfiguration.getOauthKeys();
        //add oauth key
        OAuthKeyInfo oAuthKeyInfo = new OAuthKeyInfo(OAUTH_KEY, 6000, OAuthProviderType.TYPE_AZURE);
        oAuthKeyInfo.addPublicKey(OAUTH_KEY, pubKeyBytes);
        oAuthKeyInfo.setUrl("https://login.microsoftonline.com/");
        oAuthKeyInfo.setAudience(AZURE_AUDIENCE);
        oAuthKeyInfo.setScope(AZURE_AUDIENCE + "/ejbca");
        oAuthKeyInfoLabel = oAuthKeyInfo.getLabel();
        oAuthConfiguration.addOauthKey(oAuthKeyInfo);
        globalConfigSession.saveConfiguration(authenticationToken, oAuthConfiguration);

        AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration)
                globalConfigSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        isRestEnabled = availableProtocolsConfiguration.getProtocolStatus(REST_CERTIFICATE_MANAGEMENT.getName());
        isRaWebEnabled = availableProtocolsConfiguration.getProtocolStatus(RA_WEB.getName());
        isWsEnabled = availableProtocolsConfiguration.getProtocolStatus(WS.getName());
        availableProtocolsConfiguration.setProtocolStatus(REST_CERTIFICATE_MANAGEMENT.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(RA_WEB.getName(), true);
        availableProtocolsConfiguration.setProtocolStatus(WS.getName(), true);
        globalConfigSession.saveConfiguration(authenticationToken, availableProtocolsConfiguration);

        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        adminca = CaTestUtils.createTestX509CA("CN=" + CA, "foo123".toCharArray(), false, keyusage);
        // add role
        final Role role1 = roleSession.persistRole(authenticationToken, new Role(null, ROLENAME, Arrays.asList(
                AccessRulesConstants.ROLE_ADMINISTRATOR,
                AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                StandardRules.CREATECERT.resource(),
                AccessRulesConstants.REGULAR_VIEWENDENTITY,
                AccessRulesConstants.REGULAR_CREATEENDENTITY,
                AccessRulesConstants.REGULAR_EDITENDENTITY,
                AccessRulesConstants.REGULAR_DELETEENDENTITY,
                AccessRulesConstants.REGULAR_REVOKEENDENTITY,
                AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY
        ), null));
        // Add the second RA role
        roleMember = new RoleMember(OAuth2AuthenticationTokenMetaData.TOKEN_TYPE,
                adminca.getCAId(), RoleMember.NO_PROVIDER, OAuth2AccessMatchValue.CLAIM_SUBJECT.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                OAUTH_SUB, role1.getRoleId(), null);
        roleMember.setTokenProviderId(oAuthKeyInfo.getInternalId());
        roleMember = roleMemberSession.persist(authenticationToken, roleMember);

        token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"" + OAUTH_KEY + "\",\"typ\":\"JWT\"}", "{\"sub\":\"" + OAUTH_SUB + "\", \"aud\":\"" + AZURE_AUDIENCE + "\"}", privKey);
        final String timestamp = String.valueOf((System.currentTimeMillis() + -60 * 60 * 1000) / 1000); // 1 hour old
        expiredToken = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\",\"exp\":" + timestamp + "}", privKey);
        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(getSSLFactory());
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        if (adminca != null) {
            CaTestUtils.removeCa(authenticationToken, adminca.getCAInfo());
        }
        OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        if (oAuthConfiguration.getOauthKeys().get(oAuthKeyInfoLabel) != null) {
            oAuthConfiguration.removeOauthKey(oAuthKeyInfoLabel);
            globalConfigSession.saveConfiguration(authenticationToken, oAuthConfiguration);
        }
        if (roleMember != null) {
            roleMemberSession.remove(authenticationToken, roleMember.getId());
            roleSession.deleteRoleIdempotent(authenticationToken, roleMember.getRoleId());
        }
        roleSession.deleteRoleIdempotent(authenticationToken, null,  ROLENAME);
        HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
        AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration)
                globalConfigSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        availableProtocolsConfiguration.setProtocolStatus(REST_CERTIFICATE_MANAGEMENT.getName(), isRestEnabled);
        availableProtocolsConfiguration.setProtocolStatus(RA_WEB.getName(), isRaWebEnabled);
        availableProtocolsConfiguration.setProtocolStatus(WS.getName(), isWsEnabled);
        globalConfigSession.saveConfiguration(authenticationToken, availableProtocolsConfiguration);
    }

    private static String encodeToken(final String headerJson, final String payloadJson, final PrivateKey key) {
        final StringBuilder sb = new StringBuilder();
        sb.append(Base64URL.encode(headerJson).toString());
        sb.append('.');
        sb.append(Base64URL.encode(payloadJson).toString());
        if (key != null) {
            final byte[] signature = sign(sb.toString().getBytes(StandardCharsets.US_ASCII), key);
            sb.append('.');
            sb.append(Base64URL.encode(signature).toString());
        } else {
            sb.append('.');
        }
        return sb.toString();
    }

    private static byte[] sign(final byte[] toBeSigned, final PrivateKey key) {
        try {
            return KeyTools.signData(key, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, toBeSigned);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testAdminWeb() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb");
        final HttpURLConnection connection = doGetRequest(url, token);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("EJBCA Administration should be accessible. Actual response was: " + response, response.contains("EJBCA Administration"));
    }

    @Test
    public void testAdminWebWithExpiredToken() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb");
        final HttpURLConnection connection = doGetRequest(url, expiredToken);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("Authentication should fail. Actual response was: " + response, response.contains("Authentication failed using OAuth Bearer Token"));
    }

    @Ignore
    public void testRaWeb() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/ra");
        final HttpURLConnection connection = doGetRequest(url, token);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        //Log out OauthSystemTestSub
        final String expectedString = "Log out " + OAUTH_SUB;
        assertTrue("EJBCA Administration should be accessible and contain '" + expectedString + "'. Actual response was: " + response, response.contains(expectedString));
    }

    @Test
    public void testAdminRaWithExpiredToken() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/ra");
        final HttpURLConnection connection = doGetRequest(url, expiredToken);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("Authentication should fail. Actual response was: " + response, response.contains("Log in"));
    }

    @Test
    public void testRestApiWeb() throws IOException {
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        final URL url = new URL(HTTP_REQ_PATH + "/ejbca-rest-api/v1/ca");
        final HttpURLConnection connection = doGetRequest(url, token);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("Should return JSON with ca list. Actual response was: " + response, response.contains("certificate_authorities"));
    }

    @Test
    public void testAdminRestApiWithExpiredToken() throws IOException {
        assumeTrue("Enterprise Edition only. Skipping the test", enterpriseEjbBridgeSession.isRunningEnterprise());
        final URL url = new URL(HTTP_REQ_PATH + "/ejbca-rest-api/v1/ca");
        final HttpURLConnection connection = doGetRequest(url, expiredToken);
        assertEquals("Response code was not 403", 403, connection.getResponseCode());
        String response = getResponse(connection.getErrorStream());
        assertEquals("Authentication should fail", "Forbidden", connection.getResponseMessage());
        assertTrue("Authentication should fail. Actual response was: " + response, response.contains("Authentication failed using OAuth Bearer Token"));
    }

    @Test
    public void testEjbcaWs() throws IOException, AuthorizationDeniedException_Exception, EjbcaException_Exception {
        EjbcaWS ejbcaWSPort = getEjbcaWS(token);
        List<NameAndId> availableCAs = ejbcaWSPort.getAvailableCAs();
        assertEquals("Sould return empty list of CAs", 0, availableCAs.size());
    }

    @Test
    public void testEjbcaWsWithExpiredToken() throws IOException, EjbcaException_Exception, AuthorizationDeniedException_Exception {
        exceptionRule.expect(AuthorizationDeniedException_Exception.class);
        exceptionRule.expectMessage("Authentication failed using OAuth Bearer Token");
        EjbcaWS ejbcaWSPort = getEjbcaWS(expiredToken);
        ejbcaWSPort.getAvailableCAs();
    }

    @Test
    public void testJspPage() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb/ra/listendentities.jsp");
        final HttpURLConnection connection = doGetRequest(url, token);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("Search End Entities page should be accessible. Actual response was: " + response, response.contains("<h1>Search End Entities</h1>"));
    }

    @Test
    public void testJspPageWithExpiredToken() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb/ra/listendentities.jsp");
        final HttpURLConnection connection = doGetRequest(url, expiredToken);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertTrue("Authentication should fail. Actual response was: " + response, response.contains("Authorization Denied"));

    }

    @Test
    public void testServlet() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb//profilesexport?profileType=eep");
        final HttpURLConnection connection = doGetRequest(url, token);
        assertEquals("Response code was not 200", 200, connection.getResponseCode());
        String response = getResponse(connection.getInputStream());
        assertFalse("Response body should not be empty", response.isEmpty());
    }

    @Test
    public void testServletWithExpiredToken() throws IOException {
        final URL url = new URL(HTTP_REQ_PATH + "/adminweb//profilesexport?profileType=eep");
        final HttpURLConnection connection = doGetRequest(url, expiredToken);
        assertEquals("Response code was not 200", 403, connection.getResponseCode());
        String response = getResponse(connection.getErrorStream());
        assertEquals("Authentication should fail", "Forbidden", connection.getResponseMessage());
        assertTrue("Authentication should fail. Actual response was: " + response, response.contains("Authorization Denied"));
    }

    private String getResponse(InputStream inputStream) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder sb = new StringBuilder();
        String output;
        while ((output = br.readLine()) != null) {
            sb.append(output);
        }
        return sb.toString();
    }

    private HttpsURLConnection doGetRequest(URL url, String token) throws IOException {
        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Bearer " + token);
        connection.getDoOutput();
        connection.setRequestProperty("Accept-Language", "en");
        connection.connect();
        connection.disconnect();
        return connection;
    }

    private EjbcaWS getEjbcaWS(String token) throws IOException {
        String url = "https://" + HTTP_HOST + ":" + HTTP_PORT + "/ejbca/ejbcaws/ejbcaws?wsdl";
        QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        EjbcaWSService service = new EjbcaWSService(new URL(url), qname);
        EjbcaWS ejbcaWSPort = service.getEjbcaWSPort();
        BindingProvider bindingProvider = (BindingProvider) ejbcaWSPort;
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Authorization", Collections.singletonList("Bearer " + token));
        bindingProvider.getRequestContext().put(MessageContext.HTTP_REQUEST_HEADERS, headers);
        return ejbcaWSPort;
    }

    private static SSLSocketFactory getSSLFactory() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, KeyManagementException {
        final CAInfo serverCaInfo = CaTestUtils.getServerCertCaInfo(authenticationToken);
        final List<Certificate> chain = serverCaInfo.getCertificateChain();
        Certificate serverCertificate = chain.get(0);
        final KeyStore trustKeyStore = KeyStore.getInstance("JKS");
        trustKeyStore.load(null);
        trustKeyStore.setCertificateEntry("caCert", serverCertificate);
        // we need to set properties for web service tests.
        File trustKeyStoreFile = folder.newFile(OAUTH_KEY + ".jks");
        try (FileOutputStream fileOutputStream = new FileOutputStream(trustKeyStoreFile)) {
            trustKeyStore.store(fileOutputStream, PASSWORD.toCharArray());
        }
        System.setProperty("javax.net.ssl.trustStore", trustKeyStoreFile.getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustKeyStore);
        final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return sslContext.getSocketFactory();
    }
}
