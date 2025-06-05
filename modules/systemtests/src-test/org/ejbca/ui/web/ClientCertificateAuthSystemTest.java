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
import static org.junit.Assert.assertTrue;
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
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Preconditions;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Checks that client certificate authentication and authorization is
 * working correctly in the RA UI, CA UI (AdminWeb) and in the REST interface.
 */
public class ClientCertificateAuthSystemTest {

    private static final Logger log = Logger.getLogger(ClientCertificateAuthSystemTest.class);

    private static final String TEST_NAME = ClientCertificateAuthSystemTest.class.getSimpleName();
    private static final String ROLE_NAME = TEST_NAME;

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(TEST_NAME);

    private static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    private static AvailableProtocolsConfiguration protocolConfigBackup;

    private X509Certificate serverCert;
    private X509Certificate adminClientCert;
    private KeyPair adminKeyPair;
    private int ejbcaPort = WebConfiguration.getPrivateHttpsPort();


    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass");
        CryptoProviderTools.installBCProviderIfNotAvailable();
        backupProtocolConfiguration();
        enableRestProtocolConfiguration();
        log.trace("<beforeClass");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        log.trace(">afterClass");
        restoreProtocolConfiguration();
        log.trace("<afterClass");
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
    public void testNoAuthenticationPrivatePort() throws Exception {
        try {
            adminClientCert = null;
            adminKeyPair = null;
            assertDenied();
        } catch (IOException e) {
            // If the HTTP server (e.g. Underthow in Wildfly) is set to require a certificate,
            // then the connection itself will fail, before reaching EJBCA.
        }
    }

    @Test
    public void testNoAuthenticationPublicPort() throws Exception {
        Assume.assumeTrue("This test requires 3-port separation, with a separate public port.",
                WebConfiguration.getPublicHttpsPort() != WebConfiguration.getPrivateHttpsPort());
        ejbcaPort = WebConfiguration.getPublicHttpsPort();
        adminClientCert = null;
        adminKeyPair = null;
        assertDenied();
    }

    @Test
    public void testNoAuthorization() throws Exception {
        setRoleAccess("/something_else");
        assertDenied();
    }

    @Test
    public void testSuperadminAuth() throws Exception {
        setRoleAccess("/");
        assertAllowed();
    }

    @Test
    public void testMinimalAuth() throws Exception {
        setRoleAccess("/administrator", "/ca_functionality/view_ca", "/ca");
        assertAllowed();
    }

    @Test
    public void testRaOnlyAccess() throws Exception {
        // No /administrator
        setRoleAccess("/ca_functionality/view_ca", "/ca");
        assertRaAllowed();
        assertAdminWebDenied();
        assertRestDenied();
    }

    /**
     * This test allows access, connects the EJBCA, and then revokes access.
     * <p>
     * Limitations:
     * <ul>
     * <li>Since the EJBCA systemtests use a single node, the test does not cover clustering
     *     (e.g. when the role is changed from a different node)
     * <li>It uses separate connections (no keep-alive or TLS sessions)
     * <p>
     * {@link org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImplUnitTest} cover what is not tested by this test, for the AdminWeb.
     */
    @Test
    public void testRemoveAccessRule() throws Exception {
        setRoleAccess("/administrator", "/ca_functionality/view_ca", "/ca");
        assertAllowed();
        // Remove access rules and try again
        setRoleAccess("/something_else");
        assertDenied();
    }

    /** Like {@link #testRemoveAccessRule}, but revokes access by removing the role member */
    @Test
    public void testRemoveRoleMember() throws Exception {
        setRoleAccess("/");
        assertAllowed();
        // Remove administrator from role
        removeRoleMember();
        assertDenied();
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

    private void removeRoleMember() {
        try {
            final int roleId = roleSession.getRole(alwaysAllowToken, null, ROLE_NAME).getRoleId();
            // There should only be a single role member, but remove all to be safe
            for (final RoleMember member : roleMemberSession.getRoleMembersByRoleId(alwaysAllowToken, roleId)) {
                assertTrue("Could not delete role member", roleMemberSession.remove(alwaysAllowToken, member.getId()));
            }
            assertEquals("Role member should have been removed", 0, roleMemberSession.getRoleMembersByRoleId(alwaysAllowToken, roleId).size());
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    private String fetchPage(final String uri, final int expectedResponseCode) throws MalformedURLException, IOException {
        Preconditions.checkArgument(uri.startsWith("/"));
        final String fullUrl = "https://" + WebConfiguration.getHostName() + ":" + ejbcaPort + uri;
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
        assertContainsAnyOf(html,
                // With at least one OAuth provider configured, there's an automatic redirect to login.xhtml which contains this
                "<form id=\"login\"",
                // Without any OAuth providers, there's simply a link to login.xhtml in the menu.
                "<a href=\"login.xhtml\"");
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

    /** Checks that access to the REST API is allowed */
    private void assertRestAllowed() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/ejbca-rest-api/v1/ca", 200);
        assertContains(html, "{\"certificate_authorities\":[");
    }

    /** Checks that access to the REST API is denied */
    private void assertRestDenied() throws MalformedURLException, IOException {
        final String html = fetchPage("/ejbca/ejbca-rest-api/v1/ca", 403);
        assertContains(html, "\"error_code\":403");
    }

    private void assertAllowed() throws MalformedURLException, IOException {
        assertRaAllowed();
        assertAdminWebAllowed();
        assertRestAllowed();
    }

    private void assertDenied() throws MalformedURLException, IOException {
        assertRaDenied();
        assertAdminWebDenied();
        assertRestDenied();
    }

    protected static void backupProtocolConfiguration() {
        protocolConfigBackup = (AvailableProtocolsConfiguration)
                globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }

    protected static void restoreProtocolConfiguration() throws AuthorizationDeniedException {
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, protocolConfigBackup);
    }

    protected static void enableRestProtocolConfiguration() throws AuthorizationDeniedException {
        AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration)
                globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        availableProtocolsConfiguration.setProtocolStatus(AvailableProtocols.REST_CA_MANAGEMENT.getName(), true);
        globalConfigurationSession.saveConfiguration(alwaysAllowToken, availableProtocolsConfiguration);
    }
}
