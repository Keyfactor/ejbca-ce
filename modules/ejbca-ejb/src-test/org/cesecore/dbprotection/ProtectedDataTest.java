/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.dbprotection;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.cesecore.config.ConfigurationHolder;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the ProtectedData class
 * 
 * @version $Id$
 */
public class ProtectedDataTest extends ProtectedData {

	private String rowProtection;	
	private String protectString = "This is my test protect string; with mutiple fields";
	
    @Before
    public void setUp() {
        ConfigurationHolder.instance().clear();
    }

    @Test
    public void testProtectionHMAC() throws Exception {
    	ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "false");
    	ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "false");
    	assertNull(getRowProtection());
    	protectData();
    	assertNull(getRowProtection());
    	ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid", "123");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid.0", "123");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keylabel.0","dbProtKey");
    	ConfigurationHolder.updateConfiguration("databaseprotection.classname.0","org.cesecore.keys.token.SoftCryptoToken");
    	ConfigurationHolder.updateConfiguration("databaseprotection.properties.0","dbProtKey=32fb6e53e3c8dc7425f8544dd6f4e74349b6eed47020cabd510285a478d3ef5ceae50de0d078117f932b8e9a673625b588c2f192a4c4403200d6c9f5be7d2701f3b63749dc65b1b6c88133ac2dfc395665b47c409c9a735c894eda779036db3f895e24314111d198ac3fb589a7aed8a509e45f8009028bb49dc08863ed6c9317511e4d208c7b58c5ab7f2c848e2e3e8ff828924759a6094cff1a2d076d20a247d45194e9c01d0db58346388d52d535ae133b0e23878ff2b2c5680bd0eb4eb26eb7121be72bcd79074ccda0de6c509c44159bf1e85e9079ba328815314eede888a549aa4c76bbfc92e42582311eeff86e3eb15b3a1044befd9af885ba6a9f6489");
    	ConfigurationHolder.updateConfiguration("databaseprotection.data.0","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");
    	ConfigurationHolder.updateConfiguration("databaseprotection.tokenpin.0","userpin1");
    	ConfigurationHolder.updateConfiguration("databaseprotection.version.0","1");
    	ProtectedDataConfiguration.reload();
    	protectData();
    	assertNotNull(getRowProtection());
    	assertTrue("Does not start with: 1:1:123", getRowProtection().contains("1:1:123"));
    	assertTrue("Length not > 50: "+getRowProtection().length(), getRowProtection().length() > 50);
    	assertTrue("Length not < 100: "+getRowProtection().length(), getRowProtection().length() < 100);
    	verifyData(); // will throw if fails
    	// Alter the data
    	protectString = protectString + ", and malicous data";
    	try {
    		verifyData(); // will throw if fails
    		assertTrue("Should throw", false);
    	} catch (DatabaseProtectionException e) {
    		// NOPMD
    	}
    }

    @Test
    public void testProtectionRSASig() throws Exception {
    	ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "false");
    	ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "false");
    	assertNull(getRowProtection());
    	protectData();
    	assertNull(getRowProtection());
    	ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid", "234");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid.0", "234");
    	ConfigurationHolder.updateConfiguration("databaseprotection.keylabel.0","dbStoreKey");
    	ConfigurationHolder.updateConfiguration("databaseprotection.classname.0","org.cesecore.keys.token.SoftCryptoToken");
    	ConfigurationHolder.updateConfiguration("databaseprotection.properties.0",null);
    	ConfigurationHolder.updateConfiguration("databaseprotection.data.0","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");
    	ConfigurationHolder.updateConfiguration("databaseprotection.tokenpin.0","userpin1");
    	ConfigurationHolder.updateConfiguration("databaseprotection.version.0","2");
    	ProtectedDataConfiguration.reload();
    	protectData();
    	assertNotNull(getRowProtection());
    	assertTrue("Does not start with: 1:2:234", getRowProtection().contains("1:2:234"));
    	assertTrue("Length "+getRowProtection().length(), getRowProtection().length() > 200);
    	verifyData(); // will throw if fails
    	// Alter the data
    	protectString = protectString + ", and malicous data";
    	try {
    		verifyData(); // will throw if fails
    		assertTrue("Should throw", false);
    	} catch (DatabaseProtectionException e) {
    		// NOPMD
    	}
    }
    
    @Test
    public void testProtectionECDSASig() throws Exception {
        ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "false");
        ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "false");
        assertNull(getRowProtection());
        protectData();
        assertNull(getRowProtection());
        ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.keyid", "345");
        ConfigurationHolder.updateConfiguration("databaseprotection.keyid.0", "345");
        ConfigurationHolder.updateConfiguration("databaseprotection.keylabel.0","test");
        ConfigurationHolder.updateConfiguration("databaseprotection.classname.0","org.cesecore.keys.token.SoftCryptoToken");
        ConfigurationHolder.updateConfiguration("databaseprotection.properties.0",null);
        ConfigurationHolder.updateConfiguration("databaseprotection.data.0","MIIEFQIBAzCCA9sGCSqGSIb3DQEHAaCCA8wEggPIMIIDxDCCAqcGCSqGSIb3DQEHBqCCApgwggKUAgEAMIICjQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIY0aRn+52P1cCAggAgIICYCiu9Qs4zHVjteUg8fGixRUC1+V8xUFTgsuvKDvxDc81umuImByxHrRsLOTKcUC6laGtugmBiVIEb4qd/ViGk283CW08tGj12N2HV9mrkOMXxkvLnjKzKubeb2TKdGHZ0KHqkJhqR6ApH8mCm/zeg/iy7WBNXoOrAHCoHXdyQ767rsWiatxQJPvx7Qn9IxEsbn1Iy9otcDEgxdjTUvOOQK4soSQQh0GSEAr4gnBVaVW9+1oTa0dZt30m2jhY+HCc46F9y6RGNP0JOEY0g/JmHnZjQXkW4748ZBr5YqIAA+qAmQu26chrs5jdS8Xy+ahAzhlxpLC/CPi1WE1XclUlmmHiINY3qjHFK7mXQXWrlsrU/HShsXnwOB699biSl4vUUheqW4cFpLkctMn12bkiAzS4Q/g+dUtKrce7Ws4TbJ0COENWoNU2oLM98u9QmHEEvjT9b2aaopV8n7q9LUDmJeXwKz87ORTzPH2bqC02FHaxuYDuifAuQORy7jmBigkDn9kRfVyOFJh2yfWOvJVEp1O38pDgxepk6K/5rWrm/gVPF7VdjOhgzK3k0BU3Yidn+gUoaHQ5YrEuzKnKUJzWDHT9gUNeQRiemlXwMHb6D11pf4mzHgvo6lmZa/YoMuw9gOv3IuKrNEtrGh/tawrRlOBcf//8hLfVUGB3PXVOrWx6XCQUCuDXdOa058F0O9E/IkUulxg26dHDXGf1/JKS4P4Vd2bu3pnVR68XwWT1rSumlfml4kZxNBL9Gtso9rc+5Q8T7rpje8pyHXfIqXWONQPEQ0pfLXMFWzq0r5fhDO6XMIIBFQYJKoZIhvcNAQcBoIIBBgSCAQIwgf8wgfwGCyqGSIb3DQEMCgECoIGsMIGpMBwGCiqGSIb3DQEMAQMwDgQI7WGQrD949s0CAggABIGI8IV1LQQ26QREdHC2RAMabIX4dOzb9cP2NEtHvn+0luXKRsJLMAvcoBC0cJTx3VcmUYl2j7ooko7+E2dvxEkSbPwxPUX6a4BA4712DVe6Dl116dkZlE1KGL6LZHJSbaqINXjgfLoZyS0TuIvQR5k6/1MsRxz+RHTNpjG9YXbpzhAQed2Vk7s8GDE+MBcGCSqGSIb3DQEJFDEKHggAdABlAHMAdDAjBgkqhkiG9w0BCRUxFgQUS1b1LGz5LGsGn9QNoN4z2lIY2LswMTAhMAkGBSsOAwIaBQAEFB/o+p9o89oAGjTcv+mVD84uOk4zBAhldvniMPnqKAICCAA=");
        ConfigurationHolder.updateConfiguration("databaseprotection.tokenpin.0","userpin1");
        ConfigurationHolder.updateConfiguration("databaseprotection.version.0","2");
        ConfigurationHolder.updateConfiguration("databaseprotection.sigalg.0","SHA256WithECDSA");
        ProtectedDataConfiguration.reload();
        protectData();
        assertNotNull(getRowProtection());
        assertTrue("Does not start with: 1:2:345", getRowProtection().contains("1:2:345"));
        assertTrue("Length "+getRowProtection().length(), getRowProtection().length() > 120);
        assertTrue("Length "+getRowProtection().length(), getRowProtection().length() < 180);
        verifyData(); // will throw if fails
        // Alter the data
        protectString = protectString + ", and malicous data";
        try {
            verifyData(); // will throw if fails
            assertTrue("Should throw", false);
        } catch (DatabaseProtectionException e) {
            // NOPMD
        }
    }

    //
    // Start Database integrity protection methods
    //

    @Override
    public String getRowProtection() {
        return rowProtection;
    }
    @Override
    public void setRowProtection(String rowProtection) {
        this.rowProtection = rowProtection;
    }
    @Override
    protected String getProtectString(final int version) {
        StringBuilder build = new StringBuilder(3000);
        // What is important to protect here is the data that we define, id, name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(protectString);
        return build.toString();
    }
    @Override
    protected int getProtectVersion() {
        return 1;
    }
    @Override
    protected String getRowId() {
        return "1";
    }
    //
    // End Database integrity protection methods
    //

}
