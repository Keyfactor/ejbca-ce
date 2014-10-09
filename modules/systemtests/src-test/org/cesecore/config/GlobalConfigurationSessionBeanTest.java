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

package org.cesecore.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the global configuration entity bean.
 * 
 * 
 * @version $Id$
 */
public class GlobalConfigurationSessionBeanTest extends CaTestCase {

    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private AccessControlSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GlobalConfigurationSessionBeanTest"));
    private GlobalConfiguration original = null;

    private AuthenticationToken[] nonCliAdmins;

    private Collection<Integer> caids;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        enableCLI(true);

        // First save the original
        if (original == null) {
            original = (GlobalConfiguration) this.globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        }
        caids = caSession.getAuthorizedCAs(internalAdmin);
        assertFalse("No CAs exists so this test will not work", caids.isEmpty());

        // Add the credentials and new principal
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        nonCliAdmins = new AuthenticationToken[] {
        // This authtoken should not be possible to use remotely
        new X509CertificateAuthenticationToken(principals, credentials) };
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        globalConfigurationSession.saveConfiguration(internalAdmin, original);
        enableCLI(true);
        internalAdmin = null;
    }

    public String getRoleName() {
        return "GlobalConfigurationSessionBeanTest";
    }

    /**
     * Tests adding a global configuration and waiting for the cache to be
     * updated.
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void testAddAndReadGlobalConfigurationCache() throws Exception {

        // Read a value to reset the timer
        globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        setInitialValue();

        // Set a brand new value
        GlobalConfiguration newValue = new GlobalConfiguration();
        newValue.setEjbcaTitle("BAR");
        globalConfigurationSession.saveConfiguration(internalAdmin, newValue);

        GlobalConfiguration cachedValue = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);

        cachedValue = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        assertEquals("The GlobalConfigfuration cache was not automatically updated.", "BAR", cachedValue.getEjbcaTitle());

    }

    /** Tests that NodesInCluster maintains the same order across saving 
     */
    @Test
    public void testNodesInClusterOrder() throws Exception {
        // Set a brand new value
        GlobalConfiguration gc = new GlobalConfiguration();
        Set<String> nodes = gc.getNodesInCluster();
        assertEquals("nodes should be a LinkedHashSet", "java.util.LinkedHashSet", nodes.getClass().getName());
        // Test automatic upgrade to LinkedHashSet
        HashSet<String> hs = new HashSet<String>();
        hs.add("foo");
        gc.setNodesInCluster(hs);
        nodes = gc.getNodesInCluster();
        assertEquals("nodes should be a LinkedHashSet", "java.util.LinkedHashSet", nodes.getClass().getName());
        nodes.add("node2");
        nodes.add("node1");
        nodes.add("node3");
        nodes.add("foo"); // foo already exists, and was inserted first, so it should be first in the iterator
        nodes.add("4711");
        nodes.add("bar");
        nodes.add("1node2");
        gc.setNodesInCluster(nodes);
        String str = nodes.toString();
        assertEquals("String should be the same order as inserted", "[foo, node2, node1, node3, 4711, bar, 1node2]", str);
        String str1 = gc.getNodesInCluster().toString();
        assertEquals("Strings should be the same across read and write", "[foo, node2, node1, node3, 4711, bar, 1node2]", str1);
        // Save and make sure it's ok across database saves as well
        globalConfigurationSession.saveConfiguration(internalAdmin, gc);
        globalConfigurationSession.flushCache(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        GlobalConfiguration newgc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        String str2 = newgc.getNodesInCluster().toString();
        assertEquals("Strings should be the same across read and write", "[foo, node2, node1, node3, 4711, bar, 1node2]", str2);
    }

    /**
     * Set a preliminary value and allows the cache to set it.
     * 
     * @throws InterruptedException
     */
    private void setInitialValue() throws InterruptedException, AuthorizationDeniedException {

        GlobalConfiguration initial = new GlobalConfiguration();
        initial.setEjbcaTitle("FOO");
        globalConfigurationSession.saveConfiguration(internalAdmin, initial);
    }

    /**
     * Tests that we can not pretend to be something other than command line
     * user and call the method getAvailableCAs.
     * 
     * @throws Exception
     */
    @Test
    public void testNonCLIUser_getAvailableCAs() throws Exception {
        enableCLI(true);
        for (AuthenticationToken admin : nonCliAdmins) {
            operationGetAvailabeCAs(admin);
        }
    }

    /**   
     * Tests that we can not pretend to be something other than command line
     * user and call the method getAvailableCAs.
     * 
     * @throws Exception
     */
    @Test
    public void testNonCLIUser_getCAInfo() throws Exception {
        enableCLI(true);
        boolean caught = false;
        for (AuthenticationToken admin : nonCliAdmins) {
            try {
                operationGetCAInfo(admin, caids);
                fail("AuthorizationDeniedException was not caught");
            } catch (AuthorizationDeniedException e) {
                caught = true;
            }
        }
        assertTrue("AuthorizationDeniedException was not caught", caught);
    }

    /**   
     * Tests reading and writing some values that are of special interest.
     * 
     * @throws Exception
     */
    @Test
    public void testReadingWritingValues() throws Exception {
        GlobalConfiguration gc = new GlobalConfiguration();
        assertEquals("Default value should be used in an empty created config", "foo123", gc.getAutoEnrollConnectionPwd());
        gc.setAutoEnrollConnectionPwd("bar123");
        assertEquals("We could not set value as we wanted", "bar123", gc.getAutoEnrollConnectionPwd());
        gc.setAutoEnrollConnectionPwd("");
        assertEquals("Autoenroll pwd should be possible to blank", "", gc.getAutoEnrollConnectionPwd());
    }

    /**
     * Enables/disables CLI and flushes caches unless the property does not
     * already have the right value.
     * 
     * @param enable
     * @throws AuthorizationDeniedException 
     */
    private void enableCLI(final boolean enable) throws AuthorizationDeniedException {
        final GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.flushCache(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final GlobalConfiguration newConfig;
        if (config.getEnableCommandLineInterface() == enable) {
            newConfig = config;
        } else {
            config.setEnableCommandLineInterface(enable);
            globalConfigurationSession.saveConfiguration(internalAdmin, config);
            newConfig = (GlobalConfiguration) globalConfigurationSession.flushCache(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        }
        assertEquals("CLI should have been enabled/disabled", enable, newConfig.getEnableCommandLineInterface());
        authorizationSession.forceCacheExpire();
    }

    /**
     * Try to get available CAs. Test assumes the CLI is disabled or that the
     * admin is not authorized.
     * 
     * @param admin
     *            To perform the operation with.
     */
    private void operationGetAvailabeCAs(final AuthenticationToken admin) {
        // Get some CA ids: should be empty now
        final Collection<Integer> emptyCaids = caSession.getAuthorizedCAs(admin);
        assertTrue("Should not have got any CAs as admin of type " + admin.toString(), emptyCaids.isEmpty());
    }

    /**
     * Try to get CA infos. Test assumes the CLI is disabled or that the admin
     * is not authorized.
     * 
     * @param admin
     *            to perform the operation with.
     * @param knownCaids
     *            IDs to test with.
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private void operationGetCAInfo(final AuthenticationToken admin, final Collection<Integer> knownCaids) throws CADoesntExistsException,
            AuthorizationDeniedException {
        // Get CA infos: We should not get any CA infos even if we know the IDs
        for (int caid : knownCaids) {
            final CAInfo ca = caSession.getCAInfo(admin, caid);
            assertNull("Got CA " + caid + " as admin of type " + admin.toString(), ca);
        }
    }

}
