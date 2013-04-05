/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests the ExtendedKeyUsageConfiguration class
 * 
 * @version $Id$
 */
public class ExtendedKeyUsageConfTest {

    @Before
    public void setUp() {
        ConfigurationHolder.instance().clear();
    }

    @Test
    public void testGetOids() throws Exception {
        // Create some values in a temp file and add to the configuration
        File f = File.createTempFile("testextendedkeyusageconf", "properties");
        f.deleteOnExit();
        FileWriter fos = new FileWriter(f);
        fos.write("extendedkeyusage.oid.0 = 2.5.29.37.0\nextendedkeyusage.name.0 = EKU_PKIX_ANYEXTENDEDKEYUSAGE\n");
        fos.write("extendedkeyusage.oid.1 = 1.3.6.1.5.5.7.3.21\nextendedkeyusage.name.1 = EKU_PKIX_SSHCLIENT\n");
        fos.write("extendedkeyusage.oid.2 = 1.2.840.113583.1.1.5\nextendedkeyusage.name.2 = EKU_ADOBE_PDFSIGNING\n");
        // And a few non-consecutive ones
        fos.write("extendedkeyusage.oid.4 = 2.16.840.1.113741.1.2.3\nextendedkeyusage.name.4 = EKU_INTEL_AMT\n");
        fos.write("extendedkeyusage.oid.79 = 1.3.6.1.5.2.3.5\nextendedkeyusage.name.79 = EKU_KRB_PKINIT_KDC\n");
        fos.close();
        ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
        // Now there will be some values
        List<String> oids = ExtendedKeyUsageConfiguration.getExtendedKeyUsageOids();
        assertEquals(5, oids.size());
        Map<String, String> map = ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames();
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

    }

}
