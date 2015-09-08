/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class AvailableExtendedKeyUsagesConfigTest {
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    private AvailableExtendedKeyUsagesConfiguration ekuConfigBackup;
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AvailableExtendedKeyUsagesConfigTest"));

    @Before
    public void setUp() {
        ekuConfigBackup = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(alwaysAllowToken, ekuConfigBackup);
    }
    
    @Test
    public void testGetOids() throws Exception {
        
        AvailableExtendedKeyUsagesConfiguration ekuConfig = new AvailableExtendedKeyUsagesConfiguration();
        
        ekuConfig.addExtKeyUsage("2.5.29.37.0", "EKU_PKIX_ANYEXTENDEDKEYUSAGE");
        ekuConfig.addExtKeyUsage("1.3.6.1.5.5.7.3.21", "EKU_PKIX_SSHCLIENT");
        ekuConfig.addExtKeyUsage("1.2.840.113583.1.1.5", "EKU_ADOBE_PDFSIGNING");
        ekuConfig.addExtKeyUsage("2.16.840.1.113741.1.2.3", "EKU_INTEL_AMT");
        ekuConfig.addExtKeyUsage("1.3.6.1.5.2.3.5", "EKU_KRB_PKINIT_KDC");
        
        // Now there will be some values
        List<String> oids = ekuConfig.getAllOIDs();
        assertEquals(5, oids.size());
        Map<String, String> map = ekuConfig.getAllEKUOidsAndNames();
        assertTrue(oids.contains("2.5.29.37.0")); // EKU_PKIX_ANYEXTENDEDKEYUSAGE
        assertEquals("EKU_PKIX_ANYEXTENDEDKEYUSAGE", map.get("2.5.29.37.0"));
        assertTrue(oids.contains("1.3.6.1.5.5.7.3.21")); // EKU_PKIX_SSHCLIENT
        assertEquals("EKU_PKIX_SSHCLIENT", map.get("1.3.6.1.5.5.7.3.21"));
        assertTrue(oids.contains("1.2.840.113583.1.1.5")); // EKU_ADOBE_PDFSIGNING
        assertEquals("EKU_ADOBE_PDFSIGNING", map.get("1.2.840.113583.1.1.5"));
        assertTrue(oids.contains("2.16.840.1.113741.1.2.3")); // EKU_PKIX_ANYEXTENDEDKEYUSAGE
        assertEquals("EKU_INTEL_AMT", map.get("2.16.840.1.113741.1.2.3"));
        assertTrue(oids.contains("1.3.6.1.5.2.3.5")); // EKU_PKIX_ANYEXTENDEDKEYUSAGE
        assertEquals("EKU_KRB_PKINIT_KDC", map.get("1.3.6.1.5.2.3.5"));
        // Non existing
        assertNull(map.get("1.1.1.1.1"));
        
        globalConfigSession.saveConfiguration(alwaysAllowToken, ekuConfig);
        ekuConfig = null; // just to be sure
        ekuConfig = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID);

        assertTrue(ekuConfig.isConfigurationInitialized());
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("2.5.29.37.0"));
        assertEquals("EKU_PKIX_ANYEXTENDEDKEYUSAGE", ekuConfig.getExtKeyUsageName("2.5.29.37.0"));
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.21"));
        assertEquals("EKU_PKIX_SSHCLIENT", ekuConfig.getExtKeyUsageName("1.3.6.1.5.5.7.3.21"));
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("1.2.840.113583.1.1.5"));
        assertEquals("EKU_ADOBE_PDFSIGNING", ekuConfig.getExtKeyUsageName("1.2.840.113583.1.1.5"));
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("2.16.840.1.113741.1.2.3"));
        assertEquals("EKU_INTEL_AMT", ekuConfig.getExtKeyUsageName("2.16.840.1.113741.1.2.3"));
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("1.3.6.1.5.2.3.5"));
        assertEquals("EKU_KRB_PKINIT_KDC", ekuConfig.getExtKeyUsageName("1.3.6.1.5.2.3.5"));
        // Non existing
        assertEquals("1.1.1.1.1", ekuConfig.getExtKeyUsageName("1.1.1.1.1"));
        
        ekuConfig.removeExtKeyUsage("1.3.6.1.5.5.7.3.21");
        ekuConfig.removeExtKeyUsage("2.16.840.1.113741.1.2.3");
        ekuConfig.removeExtKeyUsage("1.1.1.1.1"); // non existing
        globalConfigSession.saveConfiguration(alwaysAllowToken, ekuConfig);
        ekuConfig = null; // just to be sure
        ekuConfig = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID);
        assertEquals(3, ekuConfig.getAllOIDs().size());
        assertFalse(ekuConfig.isExtendedKeyUsageSupported("2.16.840.1.113741.1.2.3"));
        assertFalse(ekuConfig.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.21"));
        assertFalse(ekuConfig.isExtendedKeyUsageSupported("1.1.1.1.1"));
        assertTrue(ekuConfig.isExtendedKeyUsageSupported("1.3.6.1.5.2.3.5"));
        assertEquals("EKU_KRB_PKINIT_KDC", ekuConfig.getExtKeyUsageName("1.3.6.1.5.2.3.5"));
        
    }

    @Test
    public void testAddingManyExtendedKeyUsages() throws Exception {
        
        AvailableExtendedKeyUsagesConfiguration ekuConfig = new AvailableExtendedKeyUsagesConfiguration();
        
        String oid, name;
        for(int i=0; i<150; i++) {
            oid = "1.3.15." + i + ".33.12";  // random string that looks like an oid
            name = "Readable name of EKU with oid " + oid;
            ekuConfig.addExtKeyUsage(oid, name);
        }
                
        globalConfigSession.saveConfiguration(alwaysAllowToken, ekuConfig);
        ekuConfig = null; // just to be sure
        AvailableExtendedKeyUsagesConfiguration ekuConfig2 = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID);

        for(int i=0; i<150; i++) {
            oid = "1.3.15." + i + ".33.12";  // random string that looks like an oid
            name = "Readable name of EKU with oid " + oid;
            assertTrue(ekuConfig2.isExtendedKeyUsageSupported(oid));
            assertEquals(name, ekuConfig2.getExtKeyUsageName(oid));
        }

    }

    
}
