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

package org.ejbca.ui.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;

import org.apache.http.HttpResponse;
import org.apache.log4j.Logger;
import org.cesecore.WebTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Preconditions;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Checks that client certificate authentication and authorization is
 * working correctly in the RA UI and the CA UI / AdminWeb.
 */
public class ClientCertificateAuthSystemTest {

    private static final Logger log = Logger.getLogger(ClientCertificateAuthSystemTest.class);

    private static final String TEST_NAME = ClientCertificateAuthSystemTest.class.getSimpleName();
    private static final String ROLE_NAME = TEST_NAME;

    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class); 

    private X509Certificate serverCert;
    private X509Certificate adminClientCert;
    private KeyPair adminKeyPair;

    private AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(TEST_NAME);

    @BeforeClass
    public static void beforeClass() {
        log.trace(">beforeClass");
        CryptoProviderTools.installBCProviderIfNotAvailable();
        log.trace("<beforeClass");
    }

    @Before
    public void before() throws Exception {
        adminKeyPair = KeyTools.genKeys(AlgorithmConstants.SIGALG_ED25519, AlgorithmConstants.KEYALGORITHM_ED25519);
        serverCert = WebTestUtils.getServerCertificate();
        adminClientCert = WebTestUtils.setUpClientCertificate(TEST_NAME, adminKeyPair.getPublic());
    }

    @After
    public void after() throws Exception {
        log.trace(">after");
        WebTestUtils.cleanUpClientCertificate(TEST_NAME);
        log.trace("<after");
    }

    @Test
    public void testNoAccess() throws Exception {
        setRoleAccess("/something_else");
        assertRaDenied();
        assertAdminWebDenied();
    }

    @Test
    public void testSuperadminAuth() throws Exception {
        setRoleAccess("/");
        assertRaAllowed();
        assertAdminWebAllowed();
    }

    @Test
    public void testMinimalAuth() throws Exception {
        setRoleAccess("/administrator", "/ca_functionality/view_ca", "/ca");
        assertRaAllowed();
        assertAdminWebAllowed();
    }

    private void setRoleAccess(final String... accessRules) {
        try {
            final Role role = roleSession.getRole(alwaysAllowToken, null, ROLE_NAME);
            var ruleMap = new LinkedHashMap<String, Boolean>();
            for (final String rule : accessRules) {
                ruleMap.put(rule, true);
            }
            role.setAccessRules(ruleMap);
            roleSession.persistRole(alwaysAllowToken, role);
        } catch (AuthorizationDeniedException | RoleExistsException e) {
            throw new IllegalStateException(e);
        }
    }

    private String fetchPage(final String uri, final int expectedResponseCode) throws MalformedURLException, IOException {
        Preconditions.checkArgument(uri.startsWith("/"));
        final String fullUrl = "https://" + WebConfiguration.getHostName() + ":" + WebConfiguration.getPrivateHttpsPort() + uri;
        final HttpResponse response = WebTestUtils.sendGetRequest(fullUrl, serverCert, adminClientCert, adminKeyPair);
        assertEquals("Wrong HTTP response code", expectedResponseCode, response.getStatusLine().getStatusCode());
        final byte[] respBytes = WebTestUtils.getBytesFromResponse(response);
        return new String(respBytes, StandardCharsets.UTF_8);
    }

    private void assertContains(final String html, final String expected) {
        assertContainsAnyOf(html, expected);
    }

    private void assertContainsAnyOf(final String html, final String... expected) {
        for (final String search : expected) {
            if (html.contains(search)) {
                return;
            }
        }
        final String msg = "Response should contain '" + String.join("' or '", expected) + "'";
        log.error(msg + " but was:\n" + html);
        fail(msg);
    }

    /** Checks that access to the RA UI is allowed */
    private void assertRaAllowed() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/ra/", 200);
        assertContains(html, "<a href=\"cas.xhtml\"");
    }

    /** Checks that access to the RA UI is denied */
    private void assertRaDenied() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/ra/", 200);
        // TODO also allow auth error message (this only works if there's at least one OAuth provider)
        assertContainsAnyOf(html, "<form id=\"login\"");
    }

    /** Checks that access to the RA UI is allowed */
    private void assertAdminWebAllowed() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/adminweb/", 200);
        assertContains(html, "<h3 id=\"welcome\">Welcome " + TEST_NAME + " to EJBCA Administration.");
    }

    /** Checks that access to the RA UI is denied */
    private void assertAdminWebDenied() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/adminweb/", 200);
        assertContains(html, "<h1>Authorization Denied");
    }
}
