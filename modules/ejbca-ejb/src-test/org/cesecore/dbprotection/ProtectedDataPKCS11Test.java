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
package org.cesecore.dbprotection;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.cesecore.config.ConfigurationHolder;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.PKCS11CryptoTokenTest;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.Test;

/**
 * Test the ProtectedData class
 * 
 * Based on cesecore version:   
 *      ProtectedDataPKCS11Test.java 901 2011-06-21 17:29:08Z johane
 * 
 * @version $Id$
 */
public class ProtectedDataPKCS11Test extends ProtectedData {

	private String rowProtection;
	
	private String protectString = "This is my test protect string; with mutiple fields";
	
    @Before
    public void setUp() {
        CryptoProviderTools.installBCProvider();
        ConfigurationHolder.instance().clear();
    }

    @Test
    public void testProtectionDigSigPKCS11() throws Exception {
    	ConfigurationHolder.updateConfiguration("databaseprotection.enabled", "false");
    	assertNull(getRowProtection());
    	protectData();
    	assertNull(getRowProtection());
    	
    	// Create a PKCS#11 crypto token
    	CryptoToken token = PKCS11CryptoTokenTest.createPKCS11Token();
	    token.activate(PKCS11CryptoTokenTest.tokenpin.toCharArray());
	    token.deleteEntry(PKCS11CryptoTokenTest.tokenpin.toCharArray(), "dbProtKey");
	    token.generateKeyPair("1024", "dbProtKey");
	    try {
		    Properties prop = token.getProperties();
		    // Something like
		    // {sharedLibrary=/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so, slot=1}
		    // Also works without the curly braces
		    String tokenproperties = prop.toString();
		    
	    	ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "true");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "true");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid", "567");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.keyid.0", "567");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.keylabel.0","dbProtKey");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.classname.0","org.cesecore.keys.token.PKCS11CryptoToken");
	    	ConfigurationHolder.updateConfiguration("databaseprotection.properties.0", tokenproperties);
	    	ConfigurationHolder.updateConfiguration("databaseprotection.data.0",null);
	    	ConfigurationHolder.updateConfiguration("databaseprotection.tokenpin.0",PKCS11CryptoTokenTest.tokenpin);
	    	ConfigurationHolder.updateConfiguration("databaseprotection.version.0","2");
	    	ProtectedDataConfiguration.reload();
	    	protectData();
	    	assertNotNull(getRowProtection());
	    	assertTrue("Does not start with: 1:2:567", getRowProtection().contains("1:2:567"));
	    	assertTrue("Length "+getRowProtection().length(), getRowProtection().length() > 200);
	    	verifyData(); // will throw if fails
	    	// Alter the data
	    	protectString = protectString + ", and malicous data";
	    	try {
	    		verifyData(); // will throw if fails
	    		assertTrue("Should throw", false);
	    	} catch (DatabaseProtectionError e) {
	    		// NOPMD
	    	}	    	
	    } finally {
	    	token.deleteEntry(PKCS11CryptoTokenTest.tokenpin.toCharArray(), "dbProtKey");
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
