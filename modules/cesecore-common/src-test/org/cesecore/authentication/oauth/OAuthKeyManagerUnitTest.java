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
package org.cesecore.authentication.oauth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.Base64;

/**
 * Unit tests for the OAuthKeyManager class. 
 * 
 */
public class OAuthKeyManagerUnitTest {
    private OAuthKeyManager keyManager;
    private static final byte[] publicKey1 = Base64.decode(("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5sc" + 
            "wV+deHQeaRJQuM5DBYfee9TQn+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==").getBytes());

    @Before
    public void setup() {
        keyManager = new OAuthKeyManager(new ArrayList<OAuthKeyInfo>());
    }
    
    @After
    public void tearDown() {
        keyManager = null;
    }

    /**
     * Initializing OAuthKeyManager.
     */
    @Test
    public void testInitOAuthKeyManager() {
        List<OAuthKeyInfo> keys = keyManager.getAllOauthKeys();
        assertFalse(keys == null);
        assertTrue(keys.isEmpty());
    }
    
    /**
     * Adding an OAuth key.
     */
    @Test
    public void testAddOAuthKey() {
        final OAuthKeyInfo oAuthKeyInfo = new OAuthKeyInfo("test", 0, OAuthProviderType.TYPE_AZURE);
        oAuthKeyInfo.addPublicKey("test", publicKey1);
        keyManager.addOauthKey(oAuthKeyInfo);
        List<OAuthKeyInfo> keys = keyManager.getAllOauthKeys();        
        assertTrue(keys.size() == 1);
        final OAuthPublicKey oAuthPublicKey = keys.get(0).getKeys().entrySet().iterator().next().getValue();
        assertTrue(oAuthPublicKey.getKeyFingerprint() != null);
        assertTrue(oAuthPublicKey.getKeyIdentifier().equals("test"));
        assertTrue(Arrays.equals(oAuthPublicKey.getPublicKeyBytes(), publicKey1));
        assertTrue(keys.get(0).getSkewLimit() == 0);
    }
    
    /**
     * Removing a missing OAuth key.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testRemoveMissingOAuthKey() {
        keyManager.addOauthKey(new OAuthKeyInfo("test", 0, OAuthProviderType.TYPE_AZURE));
        try {
            keyManager.removeOauthKey(new OAuthKeyInfo("test2", 0, OAuthProviderType.TYPE_AZURE));
        } finally {
            assertFalse(keyManager.getAllOauthKeys().isEmpty());
        }
    }
    
    /**
     * Removing an existing OAuth key.
     */
    @Test
    public void testRemoveExistingOAuthKey() {
        OAuthKeyInfo key = new OAuthKeyInfo("test", 0, OAuthProviderType.TYPE_AZURE);
        keyManager.addOauthKey(key);
        keyManager.removeOauthKey(key);
        assertTrue(keyManager.getAllOauthKeys().isEmpty());
    }

    /**
     * Checking whether it's legal to add an OAuth key.
     */
    @Test
    public void testCanAddOAuthKey() {
        keyManager.addOauthKey(new OAuthKeyInfo("test", 0, OAuthProviderType.TYPE_AZURE));
        assertFalse(keyManager.canAdd(new OAuthKeyInfo("test", 100, OAuthProviderType.TYPE_AZURE)));
        assertTrue(keyManager.canAdd(new OAuthKeyInfo("test1", 100, OAuthProviderType.TYPE_AZURE)));
    }
    
    /**
     * Checking whether it's legal to edit an OAuth key.
     */
    @Test
    public void testCanEditOAuthKey() {
        keyManager.addOauthKey(new OAuthKeyInfo("test", 0, OAuthProviderType.TYPE_AZURE));
        OAuthKeyInfo keyToEdit = new OAuthKeyInfo("test2", 100, OAuthProviderType.TYPE_AZURE);
        keyManager.addOauthKey(keyToEdit);
        assertFalse(keyManager.canEdit(keyToEdit, "test"));
        assertTrue(keyManager.canEdit(keyToEdit, "test3"));
    }
}
