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
import com.google.common.base.Strings;
import org.apache.http.HttpStatus;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.kfenroll.ProxyCaInfo;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ca.proxyca.ProxyCaImpl;
import org.junit.After;
import org.junit.Before;
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

    private static final String TEST_NAME        = KeyFactorCommandSessionBeanSystemTest.class.getName();
    private static final String WIREMOCK_HOST    = "localhost";
    private static final String OAUTH_TOKEN_PATH = "/realms/Keyfactor/protocol/openid-connect/token";
    private static final String UPSTREAM_PATH    = "/KeyfactorAPI";
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
    private static final CaSession CA_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private String certificatesJson;
    private int proxyCaId;

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options()
            .dynamicPort()
            .dynamicHttpsPort());

    private File getResourcesDir() throws IOException {
        File currentDir = new File(".").getCanonicalFile();
        File dir = "systemtests".equals(currentDir.getName()) ?
                currentDir :
                new File(currentDir, "modules/systemtests");
        return new File(dir, "resources");
    }

    private void setUpWireMock() throws JsonProcessingException {
        configureFor("http", WIREMOCK_HOST, wireMockRule.port());
        configureFor("https", WIREMOCK_HOST, wireMockRule.httpsPort());
        // create a stub
        stubFor(post(urlEqualTo(OAUTH_TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withHeader("Content-Type", "application/x-www-form-urlencoded")
                        .withBody(VALID_TOKEN_BODY)));
        stubFor(get(urlEqualTo(UPSTREAM_PATH + "/Certificates"))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withBody(certificatesJson)));
    }

    private void removeTestProxyCa() throws AuthorizationDeniedException {
        var caIds = CA_SESSION.getAllCaIds();
        for (var caId : caIds) {
            var caInfo = CA_SESSION.getCAInfo(AUTHENTICATION_TOKEN, caId);
            if (caInfo.getName().startsWith(TEST_NAME + "-ProxyCa-")) {
                CA_SESSION.removeCA(AUTHENTICATION_TOKEN, caId);
            }
        }
    }

    private ProxyCaInfo getProxyCaInfo(final String upstreamUrl, final String oauthTokenUrl, final String oauthClientName, final String oauthClientSecret) {
        return new ProxyCaInfo(
                TEST_NAME + "-ProxyCa-" + System.currentTimeMillis(),
                "A description",
                "CN=proxy",
                CAConstants.CA_EXTERNAL,
                List.of(),
                upstreamUrl,
                List.of(),
                null,
                null,
                oauthTokenUrl,
                oauthClientName,
                oauthClientSecret,
                null,
                null
        );
    }

    private CAToken getCAToken() throws AuthorizationDeniedException {
        var caIds = CA_SESSION.getAllCaIds();
        for (var caId : caIds) {
            var caInfo = CA_SESSION.getCAInfo(AUTHENTICATION_TOKEN, caId);
            if (caInfo.getCAToken() != null) {
                return caInfo.getCAToken();
            }
        }
        throw new RuntimeException("Failed to find a CAToken. Isn't there any existing CA?");
    }

    private String getEnv(final String name, final String defaultValue) {
        final String value = System.getenv(name);
        return value == null || value.trim().isEmpty() ? defaultValue : value;
    }

    private ProxyCaInfo getProxyCaInfo() {
        final var upstreamUrl       = getEnv("UPSTREAM_URL",        "http://" + WIREMOCK_HOST + ":" + wireMockRule.port() + UPSTREAM_PATH);
        final var oauthTokenUrl     = getEnv("OAUTH_TOKEN_URL",     "http://" + WIREMOCK_HOST + ":" + wireMockRule.port() + OAUTH_TOKEN_PATH);
        final var oauthClientName   = getEnv("OAUTH_CLIENT_NAME",   "some-oath-client-name");
        final var oauthClientSecret = getEnv("OAUTH_CLIENT_SECRET", "some-oath-client-secret");
        return getProxyCaInfo(
                upstreamUrl,
                oauthTokenUrl,
                oauthClientName,
                oauthClientSecret);
    }

    private void addTestProxyCa() throws AuthorizationDeniedException, CAExistsException, InvalidAlgorithmException {
        var proxyCa = new ProxyCaImpl(getProxyCaInfo());
        proxyCa.setCAToken(getCAToken());
        CA_SESSION.addCA(AUTHENTICATION_TOKEN, proxyCa);
        proxyCaId = CA_SESSION.getCAInfo(AUTHENTICATION_TOKEN, proxyCa.getName()).getCAId();
    }

    @Before
    public void setUp() throws Exception {
        final File dir = new File(getResourcesDir(), KeyFactorCommandSessionBeanSystemTest.class.getName());
        final File certificatesJsonFile = new File(dir, "certificates.json");
        certificatesJson = Files.readString(certificatesJsonFile.toPath());
        setUpWireMock();
        removeTestProxyCa();
        addTestProxyCa();
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        removeTestProxyCa();
    }

    @Test
    public void testGetCertificates() throws Exception {
        // Given

        // When
        Map<Integer, X509Certificate> actual = KEYFACTOR_COMMAND_SESSION.getCertificates(proxyCaId);

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
        var certificates = KEYFACTOR_COMMAND_SESSION.getCertificates(proxyCaId);
        var objectMapper = new ObjectMapper();
        List<Map<String, Object>> list = objectMapper.readValue(certificatesJson, List.class);
        var map = list.get(0);
        int certificateId = (Integer)map.get("Id");
        var expected = certificates.get(certificateId);
        var json = objectMapper.writeValueAsString(map);
        stubFor(get(urlEqualTo(UPSTREAM_PATH + "/Certificates/"+certificateId)).willReturn(aResponse().withBody(json)));

        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(proxyCaId, certificateId);

        // Then
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testGetNonExistingCertificate() throws Exception {
        // Given
        var map = KEYFACTOR_COMMAND_SESSION.getCertificates(proxyCaId);
        int maxId = map.keySet()
                .stream()
                .max(Integer::compareTo)
                .orElse(0);
        int nonExistingCertificateId = maxId + 1;
        stubFor(get(urlEqualTo(UPSTREAM_PATH + "/Certificates/"+ nonExistingCertificateId))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.SC_NOT_FOUND)));


        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(proxyCaId, nonExistingCertificateId);

        // Then
        assertNull(actual);
    }

}
