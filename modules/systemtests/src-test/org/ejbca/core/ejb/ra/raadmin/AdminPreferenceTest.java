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

package org.ejbca.core.ejb.ra.raadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.AdminPreferenceProxySessionRemote;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;

/**
 * Tests the admin preference entity bean.
 */
public class AdminPreferenceTest extends CaTestCase {
    private static Logger log = Logger.getLogger(AdminPreferenceTest.class);

    private static final AuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AdminPreferenceTest"));

    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE
            .getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static TestX509CertificateAuthenticationToken authenticatedTokenCert;
    private static OAuth2AuthenticationToken authenticatedTokenOAuth;

    private AdminPreferenceSessionRemote adminPreferenceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AdminPreferenceSessionRemote.class);

    private static  AdminPreferenceProxySessionRemote adminPreferenceProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(AdminPreferenceProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private String adminFingerprint;

    @Override
    public String getRoleName() {
        return "AdminPreferenceTest";
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        authenticatedTokenCert = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
                .authenticate(new AuthenticationSubject(null, null));
        final OAuth2Principal principal = OAuth2Principal.builder()
                .setIssuer("Isser")
                .setSubject("Admin")
                .setOid("2.999.123")
                .setAudience(Collections.emptyList())
                .build();
        authenticatedTokenOAuth = new OAuth2AuthenticationToken(principal, "", "", "Provider"); // using empty token for testing
        adminFingerprint = CertTools.getFingerprintAsString(authenticatedTokenCert.getCertificate());
        cleanup();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @AfterClass
    public static void tearDownClass() {
        cleanup();
    }

    private static void cleanup() {
        adminPreferenceProxySession.deleteAdminPreferences(authenticatedTokenCert);
        adminPreferenceProxySession.deleteAdminPreferences(authenticatedTokenOAuth);
    }

    /**
     * Tests adding an administrator preference, with the administrator using a client certificate token.
     */
    @Test
    public void addAdminPreferenceCert() throws Exception {
        log.trace(">addAdminPreferenceCert()");
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        boolean ret = this.adminPreferenceSession.addAdminPreference(authenticatedTokenCert, pref);
        assertTrue("Adminpref for " + adminFingerprint + " should not exist", ret);
        ret = this.adminPreferenceSession.addAdminPreference(authenticatedTokenCert, pref);
        assertFalse("Adminpref for " + adminFingerprint + " should exist", ret);
        log.trace("<addAdminPreferenceCert()");
    }

    /**
     * Tests adding an administrator preference, with the administrator using an OAuth token.
     */
    @Test
    public void addAdminPreferenceOAuth() throws Exception {
        log.trace(">addAdminPreferenceOAuth()");
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        boolean ret = adminPreferenceSession.addAdminPreference(authenticatedTokenOAuth, pref);
        assertTrue("Adminpref for " + authenticatedTokenOAuth.getPreferredMatchValue() + " should not exist", ret);
        ret = this.adminPreferenceSession.addAdminPreference(authenticatedTokenOAuth, pref);
        assertFalse("Adminpref for " + authenticatedTokenOAuth.getPreferredMatchValue() + " should exist", ret);
        log.trace("<addAdminPreferenceOAuth()");
    }

    /**
     * Tests modifying an administrator preference
     */
    @Test
    public void modifyAdminPreference() throws Exception {
        log.trace(">modifyAdminPreference()");
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        adminPreferenceSession.addAdminPreference(authenticatedTokenCert, pref);
        pref = this.adminPreferenceSession.getAdminPreference(authenticatedTokenCert);
        assertTrue("Error Retreiving Administrator Preference.", pref.getPreferedLanguage() == 1);
        assertTrue("Error Retreiving Administrator Preference.", pref.getTheme().equals("TEST"));
        pref.setPreferedLanguage(2);
        boolean ret = this.adminPreferenceSession.changeAdminPreference(authenticatedTokenCert, pref);
        assertTrue("Adminpref for " + adminFingerprint + " should exist", ret);
        pref = this.adminPreferenceSession.getAdminPreference(authenticatedTokenCert);
        assertEquals(pref.getPreferedLanguage(), 2);
        log.trace("<modifyAdminPreference()");
    }

    @Test(expected = AuthorizationDeniedException.class)
    public void saveDefaultAdminPreferenceAuthorization() throws AuthorizationDeniedException {
        log.trace(">saveDefaultAdminPreferenceAuthorization()");
        adminPreferenceSession.saveDefaultAdminPreference(authenticatedTokenCert, null);
        log.trace("<saveDefaultAdminPreferenceAuthorization()");
    }

    @Test
    public void saveDefaultAdminPreference() throws AuthorizationDeniedException {
        log.trace(">saveDefaultAdminPreference()");
        final AdminPreference defaultAdminPreference = adminPreferenceSession.getDefaultAdminPreference();
        try {
            int language = defaultAdminPreference.getPreferedLanguage() + 1;
            AdminPreference newDefaultPreference = new AdminPreference();
            newDefaultPreference.setPreferedLanguage(language);
            adminPreferenceSession.saveDefaultAdminPreference(internalToken, newDefaultPreference);
            assertEquals(newDefaultPreference.getPreferedLanguage(), adminPreferenceSession.getDefaultAdminPreference().getPreferedLanguage());
        } finally {
            adminPreferenceSession.saveDefaultAdminPreference(internalToken, defaultAdminPreference);
        }
        log.trace("<saveDefaultAdminPreference()");
    }

}
