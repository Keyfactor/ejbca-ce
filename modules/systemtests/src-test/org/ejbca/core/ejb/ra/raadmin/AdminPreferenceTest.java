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

package org.ejbca.core.ejb.ra.raadmin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
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
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */

    private SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper
            .INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class);

    TestX509CertificateAuthenticationToken internalAdmin;

    private AdminPreferenceSessionRemote raAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AdminPreferenceSessionRemote.class);

    private String user;

    public String getRoleName() {
        return "AdminPreferenceTest";
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        internalAdmin = (TestX509CertificateAuthenticationToken) simpleAuthenticationProvider
        .authenticate(new AuthenticationSubject(null, null));
        user = CertTools.getFingerprintAsString(internalAdmin.getCertificate());
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
        boolean ret = this.raAdminSession.addAdminPreference(internalAdmin, pref);
        assertTrue("Adminpref for " + user + " should not exist", ret);
        ret = this.raAdminSession.addAdminPreference(internalAdmin, pref);
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
        raAdminSession.addAdminPreference(internalAdmin, pref);
        pref = this.raAdminSession.getAdminPreference(user);
        assertTrue("Error Retreiving Administrator Preference.", pref.getPreferedLanguage() == 1);
        assertTrue("Error Retreiving Administrator Preference.", pref.getTheme().equals("TEST"));
        pref.setPreferedLanguage(2);
        boolean ret = this.raAdminSession.changeAdminPreference(internalAdmin, pref);
        assertTrue("Adminpref for " + user + " should exist", ret);
        pref = this.raAdminSession.getAdminPreference(user);
        assertEquals(pref.getPreferedLanguage(), 2);
        log.trace("<test02ModifyAdminPreference()");
    }

}
