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

import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.config.ConfigurationHolder;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.string.StringConfigurationCache;

import static org.junit.Assert.assertEquals;

/**
 * A unit test for static configuration and log value filtering.
 */
public class ScepConfigurationTest {
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testGetSetAndFiltering() {

        // Well known encryption password, default will result in the same string every time, 
        // if a specific value is set it will be more modern encryption with a salt giving different values every time
        StringConfigurationCache.INSTANCE.setEncryptionKey("qhrnf.f8743;12%#75".toCharArray());

        ScepConfiguration config = new ScepConfiguration();
        config.addAlias("alias1");
        config.addAlias("alias2");
        config.setClientCertificateRenewal("alias1", true);
        config.setClientCertificateRenewal("alias3", true); // alias does not exist, value not set
        config.setRAAuthpassword("alias2", "foo123");
        config.setRAEndEntityProfile("alias2", "name1");
        config.setIntuneProxyHost("alias2", "host");
        assertEquals(true, config.getClientCertificateRenewal("alias1"));
        assertEquals(false, config.getClientCertificateRenewal("alias2")); // default value
        assertEquals(false, config.getClientCertificateRenewal("alias3")); // default value when alias does not exist
        assertEquals("foo123", config.getRAAuthPassword("alias2"));
        assertEquals("", config.getRAAuthPassword("alias1"));
        assertEquals("", config.getIntuneProxyPass("alias2"));
        assertEquals("", config.getIntuneAadAppKey("alias2"));
        
        @SuppressWarnings("unchecked")
        ScepConfiguration config2 = new ScepConfiguration((LinkedHashMap<Object, Object>) config.saveData());
        config2.setRAAuthpassword("alias2", "bar123");
        config2.setRAEndEntityProfile("alias2", "name2");
        config2.setIntuneProxyHost("alias2", null);
        config2.setIntuneAadAppKey("alias2", "appkey123");
        config2.setIntuneProxyPass("alias2", "pass");
        assertEquals("pass", config2.getIntuneProxyPass("alias2"));
        assertEquals("appkey123", config2.getIntuneAadAppKey("alias2"));
        Map<Object,Object> diff = config.diff(config2);
        // Default encryption password gives the same value all the time
        assertEquals("{changed:alias2.ra.entityProfile=name2, changed:alias2.ra.authPwd=4794b442dc3e3d400ba2ed53b1893d19, changed:alias2.intuneAadAppKey=d4dadc043bf1580f6c5ef8130c92ecde, changed:alias2.intuneProxyHost=, changed:alias2.intuneProxyPass=5ff8352c1dd5e17733df37922498cb90}", diff.toString());
        config.filterDiffMapForLogging(diff);
        assertEquals("{changed:alias2.ra.entityProfile=name2, changed:alias2.ra.authPwd=hidden, changed:alias2.intuneAadAppKey=hidden, changed:alias2.intuneProxyHost=, changed:alias2.intuneProxyPass=hidden}", diff.toString());
        
    }
}
