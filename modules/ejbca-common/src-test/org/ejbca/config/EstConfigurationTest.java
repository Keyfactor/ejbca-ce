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
package org.ejbca.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.string.StringConfigurationCache;



/**
 * A unit test for static configuration and log value filtering.
 */
public class EstConfigurationTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testGetSetAndFiltering() {

        // Well known encryption password, default will result in the same string every time, 
        // if a specific value is set it will be more modern encryption with a salt giving different values every time
        StringConfigurationCache.INSTANCE.setEncryptionKey("qhrnf.f8743;12%#75".toCharArray());

        EstConfiguration config = new EstConfiguration();
        config.addAlias("alias1");
        config.addAlias("alias2");
        config.addAlias("alias4");
        config.setAllowChangeSubjectName("alias1", true);
        config.setAllowChangeSubjectName("alias3", true); // alias does not exist, value not set
        config.setPassword("alias2", "foo123");
        config.setRANameGenPostfix("alias2", "name1");
        config.setVendorMode("alias4", true);
        config.setVendorCaIds("alias4", "1:2:4");
        assertEquals(true, config.getAllowChangeSubjectName("alias1"));
        assertEquals(false, config.getAllowChangeSubjectName("alias2")); // default value
        assertEquals(false, config.getAllowChangeSubjectName("alias3")); // default value when alias does not exist
        assertEquals("foo123", config.getPassword("alias2"));
        assertEquals("", config.getPassword("alias1"));
        assertTrue(config.getVendorMode("alias4"));
        assertEquals("1:2:4", config.getVendorCaIds("alias4"));
        assertEquals("", config.getVendorCaIds("alias1"));
        
        EstConfiguration config2 = new EstConfiguration(config);
        config2.setPassword("alias2", "bar123");
        config2.setRANameGenPostfix("alias2", "name2");
        assertEquals("name2", config2.getRANameGenPostfix("alias2"));
        assertEquals("bar123", config2.getPassword("alias2"));
        Map<Object,Object> diff = config.diff(config2);
        // Default encryption password gives the same value all the time
        assertEquals("{changed:alias2.reqpassword=4794b442dc3e3d400ba2ed53b1893d19, changed:alias2.ra.namegenerationpostfix=name2}", diff.toString());
        config.filterDiffMapForLogging(diff);
        assertEquals("{changed:alias2.reqpassword=hidden, changed:alias2.ra.namegenerationpostfix=name2}", diff.toString());
        
    }
}
