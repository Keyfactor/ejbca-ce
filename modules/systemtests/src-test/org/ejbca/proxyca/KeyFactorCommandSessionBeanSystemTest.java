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

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.http.HttpStatus;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import wiremock.com.fasterxml.jackson.core.JsonProcessingException;
import wiremock.com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class KeyFactorCommandSessionBeanSystemTest {

    private static final String TEST_NAME = KeyFactorCommandSessionBeanSystemTest.class.getName();
    private static final String WIREMOCK_HOST = "localhost";
    private static final String TOKEN_PATH = "/realms/Keyfactor/protocol/openid-connect/token";
    private static final String CLIENT_ID = "some_client_id";
    private static final String CLIENT_SECRET = "some_client_secret";
    private static final String VALID_TOKEN_BODY = """
{
    "access_token": "valid-token",
    "expires_in": 1800,
    "refresh_expires_in": 0,
    "token_type": "Bearer",
    "not-before-policy": 0,
    "scope": "email profile"
}
""";
    private static final AuthenticationToken AUTHENTICATION_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(TEST_NAME));
    private static final KeyFactorCommandSession KEYFACTOR_COMMAND_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyFactorCommandSessionRemote.class, EjbRemoteHelper.MODULE_EJBCA);
    private static final GlobalConfigurationSession GLOBAL_CONFIGURATION_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_CESECORE);
    private static String certificatesJson;
    private static int nonExistingCertificateId;

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options()
            .dynamicPort()
            .dynamicHttpsPort());

    private static File getResourcesDir() throws IOException {
        File currentDir = new File(".").getCanonicalFile();
        File dir = "systemtests".equals(currentDir.getName()) ?
                currentDir :
                new File(currentDir, "modules/systemtests");
        return new File(dir, "resources");
    }

    @BeforeClass
    public static void setUpClass() throws IOException {
        final File dir = new File(getResourcesDir(), KeyFactorCommandSessionBeanSystemTest.class.getName());
        final File certificatesJsonFile = new File(dir, "certificates.json");
        certificatesJson = Files.readString(certificatesJsonFile.toPath());
    }

    private void removeOAuthConfiguration() throws AuthorizationDeniedException {
        final var oAuthConfiguration = (OAuthConfiguration) GLOBAL_CONFIGURATION_SESSION.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        if (oAuthConfiguration.getOauthKeyByLabel(TEST_NAME) != null) {
            oAuthConfiguration.removeOauthKey(TEST_NAME);
        }
        GLOBAL_CONFIGURATION_SESSION.saveConfiguration(AUTHENTICATION_TOKEN, oAuthConfiguration);
    }

    private void configureWireMock() throws JsonProcessingException {
        configureFor("http", WIREMOCK_HOST, wireMockRule.port());
        configureFor("https", WIREMOCK_HOST, wireMockRule.httpsPort());
        // create a stub
        stubFor(post(urlEqualTo(TOKEN_PATH)).willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBody(VALID_TOKEN_BODY)));
        stubFor(get(urlEqualTo("/Certificates")).willReturn(aResponse().withBody(certificatesJson)));
        var objectMapper = new ObjectMapper();
        List<Map<String, Object>> maps = objectMapper.readValue(certificatesJson, List.class);
        int maxId = 0;
        for (var map : maps) {
            int id = (Integer)map.get("Id");
            maxId = Math.max(maxId, id);
            var json = objectMapper.writeValueAsString(map);
            stubFor(get(urlEqualTo("/Certificates/"+id)).willReturn(aResponse().withBody(json)));
        }
        nonExistingCertificateId = maxId+1;
        stubFor(get(urlEqualTo("/Certificates/"+ nonExistingCertificateId)).willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));
    }

    @Before
    public void setUp() throws Exception {
        removeOAuthConfiguration();
        configureWireMock();
        final var oAuthConfiguration = (OAuthConfiguration) GLOBAL_CONFIGURATION_SESSION.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        OAuthKeyInfo oAuthKeyInfo = new OAuthKeyInfo(TEST_NAME, 0, OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK);
        oAuthKeyInfo.setUrl("http://"+WIREMOCK_HOST+":"+ wireMockRule.port());
        oAuthKeyInfo.setRealm("Keyfactor");
        oAuthKeyInfo.setTokenUrl("http://"+WIREMOCK_HOST+":"+ wireMockRule.port() +TOKEN_PATH);
        oAuthKeyInfo.setClient(CLIENT_ID);
        oAuthKeyInfo.setClientSecret(CLIENT_SECRET);
        oAuthConfiguration.addOauthKey(oAuthKeyInfo);
        GLOBAL_CONFIGURATION_SESSION.saveConfiguration(AUTHENTICATION_TOKEN, oAuthConfiguration);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        removeOAuthConfiguration();
    }

    @Test
    public void testGetCertificates() throws Exception {
        // Given

        // When
        Map<Integer, X509Certificate> actual = KEYFACTOR_COMMAND_SESSION.getCertificates(TEST_NAME);

        // Then
        assertNotNull(actual);
        assertFalse("There are no certificates", actual.isEmpty());
        for (var entry : actual.entrySet()) {
            assertNotNull("Certificate with key="+entry.getKey()+" is null", entry.getValue());
        }
    }

    @Test
    public void testGetExistingCertificate() throws Exception {
        // Given
        var certificates = KEYFACTOR_COMMAND_SESSION.getCertificates(TEST_NAME);
        var entry = certificates.entrySet().iterator().next();
        int id = entry.getKey();
        X509Certificate expected = entry.getValue();

        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(TEST_NAME, id);

        // Then
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testGetNonExistingCertificate() throws Exception {
        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(TEST_NAME, nonExistingCertificateId);

        // Then
        assertNull(actual);
    }

}
