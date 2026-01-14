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

    private static final String TEST_NAME = KeyFactorCommandSessionBeanSystemTest.class.getName();
    private static final String WIREMOCK_HOST = "localhost";
    private static final String OAUTH_TOKEN_PATH = "/realms/Keyfactor/protocol/openid-connect/token";
    private static final String OAUTH_PATH = "/KeyfactorAPI";
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
    private int nonExistingCertificateId;
    private String oauthTokenUrl;
    private String oauthUrl;
    private String oauthClientName;
    private String oauthClientSecret;
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
        stubFor(get(urlEqualTo("/KeyfactorAPI/Certificates"))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.SC_OK)
                        .withBody(certificatesJson)));
        var objectMapper = new ObjectMapper();
        List<Map<String, Object>> maps = objectMapper.readValue(certificatesJson, List.class);
        int maxId = 0;
        for (var map : maps) {
            int certificateId = (Integer)map.get("Id");
            maxId = Math.max(maxId, certificateId);
            var json = objectMapper.writeValueAsString(map);
            stubFor(get(urlEqualTo("/KeyfactorAPI/Certificates/"+certificateId)).willReturn(aResponse().withBody(json)));
        }
        nonExistingCertificateId = maxId+1;
        stubFor(get(urlEqualTo("/KeyfactorAPI/Certificates/"+ nonExistingCertificateId))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.SC_NOT_FOUND)));
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

    private ProxyCaInfo getProxyCaInfo() {
        return new ProxyCaInfo(
                TEST_NAME + "-ProxyCa-" + System.currentTimeMillis(),
                "A description",
                "CN=proxy",
                CAConstants.CA_EXTERNAL,
                List.of(),
                null,
                List.of(),
                null,
                null,
                oauthTokenUrl,
                oauthUrl,
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

    private void addTestProxyCa() throws AuthorizationDeniedException, CAExistsException, InvalidAlgorithmException {
        oauthTokenUrl     = "http://" + WIREMOCK_HOST + ":" + wireMockRule.port() + OAUTH_TOKEN_PATH;
        oauthUrl          = "http://" + WIREMOCK_HOST + ":" + wireMockRule.port() + OAUTH_PATH;
        oauthClientName   = "some-oath-client-name";
        oauthClientSecret = "some-oath-client-secret";
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
        var entry = certificates.entrySet().iterator().next();
        int certificateId = entry.getKey();
        X509Certificate expected = entry.getValue();

        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(proxyCaId, certificateId);

        // Then
        assertNotNull(actual);
        assertEquals(expected, actual);
    }

    @Test
    public void testGetNonExistingCertificate() throws Exception {
        // When
        var actual = KEYFACTOR_COMMAND_SESSION.getCertificate(proxyCaId, nonExistingCertificateId);

        // Then
        assertNull(actual);
    }

}
