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
import static org.junit.Assert.fail;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the admin preference entity bean.
 *
 * @version $Id$
 */
public class AdminPreferenceTest extends CaTestCase {
    private static Logger log = Logger.getLogger(AdminPreferenceTest.class);

    private static final AuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AdminPreferenceTest"));

    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE
            .getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private TestX509CertificateAuthenticationToken authenticatedToken;

    private AdminPreferenceSessionRemote adminPreferenceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AdminPreferenceSessionRemote.class);

    private String user;

    public String getRoleName() {
        return "AdminPreferenceTest";
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        authenticatedToken = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
                .authenticate(new AuthenticationSubject(null, null));
        user = CertTools.getFingerprintAsString(authenticatedToken.getCertificate());
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * tests adding an administrator preference
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void testAddAdminPreference() throws Exception {
        log.trace(">test01AddAdminPreference()");
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        boolean ret = this.adminPreferenceSession.addAdminPreference(authenticatedToken, pref);
        assertTrue("Adminpref for " + user + " should not exist", ret);
        ret = this.adminPreferenceSession.addAdminPreference(authenticatedToken, pref);
        assertFalse("Adminpref for " + user + " should exist", ret);
        log.trace("<test01AddAdminPreference()");
    }

    /**
     * tests modifying an administrator preference
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void testModifyAdminPreference() throws Exception {
        log.trace(">test02ModifyAdminPreference()");
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        adminPreferenceSession.addAdminPreference(authenticatedToken, pref);
        pref = this.adminPreferenceSession.getAdminPreference(user);
        assertTrue("Error Retreiving Administrator Preference.", pref.getPreferedLanguage() == 1);
        assertTrue("Error Retreiving Administrator Preference.", pref.getTheme().equals("TEST"));
        pref.setPreferedLanguage(2);
        boolean ret = this.adminPreferenceSession.changeAdminPreference(authenticatedToken, pref);
        assertTrue("Adminpref for " + user + " should exist", ret);
        pref = this.adminPreferenceSession.getAdminPreference(user);
        assertEquals(pref.getPreferedLanguage(), 2);
        log.trace("<test02ModifyAdminPreference()");
    }

    @Test
    public void testSaveDefaultAdminPreferenceAuthorization() {
        boolean caught = false;
        try {
            adminPreferenceSession.saveDefaultAdminPreference(authenticatedToken, null);
            fail("Authorization should have thrown exception");
        } catch (AuthorizationDeniedException e) {
            caught = true;
        }
        assertTrue("Authorization should have thrown exception", caught);
    }

    @Test
    public void testSaveDefaultAdminPreference() throws AuthorizationDeniedException {
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

    }

}
