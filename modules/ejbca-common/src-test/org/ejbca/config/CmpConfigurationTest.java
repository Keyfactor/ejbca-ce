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

import java.util.Map;

import org.cesecore.config.ConfigurationHolder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A unit test for static configuration and log value filtering.
 */
public class CmpConfigurationTest {

    @Test
    public void testGetSetAndFiltering() {

        // Well known encryption password, default will result in the same string every time, 
        // if a specific value is set it will be more modern encryption with a salt giving different values every time
        ConfigurationHolder.updateConfiguration("password.encryption.key", null);

        CmpConfiguration config = new CmpConfiguration();
        config.addAlias("alias1");
        config.addAlias("alias2");
        config.setAllowRAVerifyPOPO("alias1", true);
        config.setAllowRAVerifyPOPO("alias3", true); // alias does not exist, value not set
        config.setAuthenticationModule("alias2", "HMAC");
        config.setAuthenticationParameters("alias2", "foo123");
        config.setRACAName("alias2", "name1");
        config.setVendorMode("alias1", true);
        config.setVendorCaIds("alias1", "1:55");
        assertEquals(true, config.getAllowRAVerifyPOPO("alias1"));
        assertEquals(false, config.getAllowRAVerifyPOPO("alias2")); // default value
        assertEquals(false, config.getAllowRAVerifyPOPO("alias3")); // default value when alias does not exist
        assertEquals("foo123", config.getAuthenticationParameters("alias2"));
        assertEquals("foo123", config.getAuthenticationParameter("HMAC", "alias2"));
        assertEquals("", config.getAuthenticationParameter("dummy", "alias2"));
        assertEquals("-;-", config.getAuthenticationParameters("alias1"));
        assertTrue(config.getVendorMode("alias1"));
        assertEquals("1:55", config.getVendorCaIds("alias1"));
        assertEquals("", config.getVendorCaIds("alias2"));
        
        CmpConfiguration config2 = new CmpConfiguration(config);
        config2.setAuthenticationParameters("alias2", "bar123");
        config2.setRACAName("alias2", "name2");
        Map<Object,Object> diff = config.diff(config2);
        // Default encryption password gives the same value all the time
        assertEquals("{changed:alias2.authenticationparameters=4794b442dc3e3d400ba2ed53b1893d19, changed:alias2.ra.caname=name2}", diff.toString());
        config.filterDiffMapForLogging(diff);
        assertEquals("{changed:alias2.authenticationparameters=hidden, changed:alias2.ra.caname=name2}", diff.toString());
        
    }
}
