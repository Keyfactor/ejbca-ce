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

import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionRemote;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the global configuration entity bean.
 */
public class GlobalConfigurationSessionBeanTest extends CaTestCase {

    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private AuthorizationSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSessionRemote.class);
    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("GlobalConfigurationSessionBeanTest");

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
        caids = caSession.getAuthorizedCaIds(internalAdmin);
        assertFalse("No CAs exists so this test will not work", caids.isEmpty());

        // Add the credentials and new principal
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        // This authtoken should not be possible to use remotely
        nonCliAdmins = new AuthenticationToken[] { new X509CertificateAuthenticationToken(certificate) };
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        globalConfigurationSession.saveConfiguration(internalAdmin, original);
        enableCLI(true);
        internalAdmin = null;
    }

    @Test
    public void testOcspConfigurationWriteFlushAndRead() throws AuthorizationDeniedException {
        final GlobalOcspConfiguration backup = (GlobalOcspConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        try {
            final GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            ocspConfiguration.setIsOcspAuditLoggingEnabled(false);
            assertFalse(ocspConfiguration.getIsOcspAuditLoggingEnabled());
            // ocspConfiguration is a copy, setting properties on this object does not modify the cache
            ocspConfiguration.setIsOcspAuditLoggingEnabled(true);
            assertTrue(ocspConfiguration.getIsOcspAuditLoggingEnabled());
            final GlobalOcspConfiguration ocspConfiguration2 = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            // since we modified a copy and didn't save our changes isOcspAuditLoggingEnabled should still be false
            // in the cache
            assertFalse(ocspConfiguration2.getIsOcspAuditLoggingEnabled());
            // After flushing, we should get a new object constructed from data in the database
            globalConfigurationSession.flushConfigurationCache(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            final GlobalOcspConfiguration ocspConfiguration3 = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertFalse(ocspConfiguration3.getIsOcspAuditLoggingEnabled());
            // Let try to set isOcspAuditLoggingEnabled to true and save. Now the changes should
            // be written both to the database and the cache.
            ocspConfiguration3.setIsOcspAuditLoggingEnabled(true);
            globalConfigurationSession.saveConfiguration(internalAdmin, ocspConfiguration3);
            final GlobalOcspConfiguration ocspConfiguration4 = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertTrue(ocspConfiguration4.getIsOcspAuditLoggingEnabled());
            globalConfigurationSession.flushConfigurationCache(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            // Since the cache was flushed, this will retrieve data from the database
            final GlobalOcspConfiguration ocspConfiguration5 = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertTrue(ocspConfiguration5.getIsOcspAuditLoggingEnabled());
        } finally {
            globalConfigurationSession.saveConfiguration(internalAdmin, backup);
        }
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
     * Enables/disables CLI and flushes caches unless the property does not
     * already have the right value.
     * 
     * @param enable
     * @throws AuthorizationDeniedException 
     */
    private void enableCLI(final boolean enable) throws AuthorizationDeniedException {
        final GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final GlobalConfiguration newConfig;
        if (config.getEnableCommandLineInterface() == enable) {
            newConfig = config;
        } else {
            config.setEnableCommandLineInterface(enable);
            globalConfigurationSession.saveConfiguration(internalAdmin, config);
            newConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
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
        final Collection<Integer> emptyCaids = caSession.getAuthorizedCaIds(admin);
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
    
    @Test
    public void testSaveCtLog() throws Exception {
        GlobalConfiguration globalconfigurationBkup = 
                (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        try {
            GlobalConfiguration globalconfiguration = 
                    (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            
            LinkedHashMap<Integer,CTLogInfo> ctlogs = new LinkedHashMap<>();
            KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
            CTLogInfo ctLog0 = new CTLogInfo("https://first.one", keys.getPublic().getEncoded(), "firstCtTag", 4000);
            CTLogInfo ctLog1 = new CTLogInfo("https://back.for.seconds", keys.getPublic().getEncoded(), "secondCtTag", 4000);
            ctLog1.setIntervalStart(new Date());
            ctLog1.setIntervalEnd(new Date());
            CTLogInfo ctLog2 = new CTLogInfo("https://finally.third", keys.getPublic().getEncoded(), "thirdCtTag", 4000);
            ctLog2.setExpirationYearRequired(2022);
            ctlogs.put(ctLog0.getLogId(), ctLog0);
            ctlogs.put(ctLog1.getLogId(), ctLog1);
            ctlogs.put(ctLog2.getLogId(), ctLog2);
            globalconfiguration.setCTLogs(ctlogs);
            globalConfigurationSession.saveConfiguration(internalAdmin, globalconfiguration);
            
            // reload
            globalconfiguration = 
                    (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            
            LinkedHashMap<Integer,CTLogInfo> savedCtlogs = globalconfiguration.getCTLogs();
            assertEquals("CT logs count did not match", savedCtlogs.size(), 3);
            
            assertEquals("CT logs 1 url did not match", savedCtlogs.get(ctLog0.getLogId()).getUrl(), "https://first.one");
            assertEquals("CT logs 2 url did not match", savedCtlogs.get(ctLog1.getLogId()).getUrl(), "https://back.for.seconds");
            assertEquals("CT logs 3 url did not match", savedCtlogs.get(ctLog2.getLogId()).getUrl(), "https://finally.third");
            
            assertEquals("CT logs pubkey did not match", 
                    Hex.toHexString(savedCtlogs.get(ctLog0.getLogId()).getPublicKeyBytes()), 
                    Hex.toHexString(keys.getPublic().getEncoded()));
            
            assertNotNull("CT logs 2 start date is null", savedCtlogs.get(ctLog1.getLogId()).getIntervalStart());
            assertNotNull("CT logs 2 end date is null", savedCtlogs.get(ctLog1.getLogId()).getIntervalEnd());
            assertEquals("CT logs 3 url did not match", 
                    savedCtlogs.get(ctLog2.getLogId()).getExpirationYearRequired().intValue(), 2022);
            
            
        } finally {
            globalConfigurationSession.saveConfiguration(internalAdmin, globalconfigurationBkup);
        }
    }

}
