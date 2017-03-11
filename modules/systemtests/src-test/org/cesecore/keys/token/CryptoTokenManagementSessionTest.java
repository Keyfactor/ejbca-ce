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
package org.cesecore.keys.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests CryptoToken management API.
 * 
 * @version $Id$
 */
public class CryptoTokenManagementSessionTest extends RoleUsingTestCase {

    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(CryptoTokenManagementSessionTest.class.getSimpleName());
    private static final Logger log = Logger.getLogger(CryptoTokenManagementSessionTest.class);
    
    @BeforeClass
    public static void setUpProviderAndCreateCA() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        super.setUpAuthTokenAndRole(null, this.getClass().getSimpleName(), Arrays.asList(CryptoTokenRules.BASE.resource()), null);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDownRemoveRole();
    }

    @Test
    public void basicCryptoTokenForCAWithImpliedRSA() throws Exception {
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testCaRsa", "1024");
            subTest(cryptoTokenId, "1024");
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(roleMgmgToken, cryptoTokenId);
        }
    }
    
    @Test
    public void basicCryptoTokenForCAWithExplicitRSA() throws Exception {
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testCaRsa", "RSA1024");
            subTest(cryptoTokenId, "RSA1024");
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(roleMgmgToken, cryptoTokenId);
        }
    }

    @Test
    public void basicCryptoTokenForCAWithDSA() throws Exception {
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testCaDsa", "DSA1024");
            subTest(cryptoTokenId, "DSA1024");
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(roleMgmgToken, cryptoTokenId);
        }
    }

    @Test
    public void basicCryptoTokenForCAWithECDSA() throws Exception {
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testCaEcdsa", "secp256r1");
            subTest(cryptoTokenId, "secp256r1");
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(roleMgmgToken, cryptoTokenId);
        }
    }

    private void subTest(final int cryptoTokenId, final String keySpec) throws Exception {
        // Test additional key creation and informatin retrieval
        final String KEYALIAS1 = "newAlias1";
        final String KEYALIAS2 = "newAlias2";
        final String KEYALIAS_BAD = "notAnAlias";
        cryptoTokenManagementSession.createKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS1, keySpec);
        try {
            cryptoTokenManagementSession.createKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS1, keySpec);
            fail("Should not be able to generate a key pair with the same alias twice.");
        } catch (InvalidKeyException e) {
            // Expected
        }
        try {
            cryptoTokenManagementSession.createKeyPairWithSameKeySpec(roleMgmgToken, cryptoTokenId, KEYALIAS1, KEYALIAS1);
            fail("Should not be able to generate a key pair with the same alias twice.");
        } catch (InvalidKeyException e) {
            // Expected
        }
        cryptoTokenManagementSession.createKeyPairWithSameKeySpec(roleMgmgToken, cryptoTokenId, KEYALIAS1, KEYALIAS2);
        assertNull("Non-existing key alias should not return info.", cryptoTokenManagementSession.getKeyPairInfo(roleMgmgToken, cryptoTokenId, KEYALIAS_BAD));
        final KeyPairInfo keyPairInfo1 = cryptoTokenManagementSession.getKeyPairInfo(roleMgmgToken, cryptoTokenId, KEYALIAS1);
        assertEquals("Got wrong info for the requested alias.", KEYALIAS1, keyPairInfo1.getAlias());
        final KeyPairInfo keyPairInfo2 = cryptoTokenManagementSession.getKeyPairInfo(roleMgmgToken, cryptoTokenId, KEYALIAS2);
        assertEquals("Got wrong info for the requested alias.", KEYALIAS2, keyPairInfo2.getAlias());
        assertEquals("Key spec re-use failed.", keyPairInfo1.getKeyAlgorithm(), keyPairInfo2.getKeyAlgorithm());
        assertEquals("Key spec re-use failed.", keyPairInfo1.getKeySpecification(), keyPairInfo2.getKeySpecification());
        // Test key listing
        final List<KeyPairInfo> keyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(roleMgmgToken, cryptoTokenId);
        final List<String> aliases = cryptoTokenManagementSession.getKeyPairAliases(roleMgmgToken, cryptoTokenId);
        assertEquals("Number of aliases and returned key pair informations should be the same.", keyPairInfos.size(), aliases.size());
        for (final KeyPairInfo keyPairInfo : keyPairInfos) {
            assertTrue("List of aliases was missing " + keyPairInfo.getAlias(), aliases.contains(keyPairInfo.getAlias()));
        }
        // Test key test
        cryptoTokenManagementSession.testKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS1);
        cryptoTokenManagementSession.testKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS2);
        try {
            cryptoTokenManagementSession.testKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS_BAD);
            fail("Key test should throw for non-existing key.");
        } catch (CryptoTokenOfflineException e) {
            // Expected
        }
        // Test key removal
        cryptoTokenManagementSession.removeKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS2);
        assertNull("Non-existing key alias should not return info.", cryptoTokenManagementSession.getKeyPairInfo(roleMgmgToken, cryptoTokenId, KEYALIAS2));
        try {
            cryptoTokenManagementSession.removeKeyPair(roleMgmgToken, cryptoTokenId, KEYALIAS2);
            fail("Key removal should throw for non-existing key.");
        } catch (InvalidKeyException e) {
            // Expected
        }
        // Verify auto-activation behavior
        assertTrue("Expected CryptoToken to be active.", cryptoTokenManagementSession.isCryptoTokenStatusActive(roleMgmgToken, cryptoTokenId));
        cryptoTokenManagementSession.deactivate(roleMgmgToken, cryptoTokenId);
        assertTrue("Expected auto-activated CryptoToken to still be active.", cryptoTokenManagementSession.isCryptoTokenStatusActive(roleMgmgToken, cryptoTokenId));
        cryptoTokenManagementSession.activate(roleMgmgToken, cryptoTokenId, "badCode".toCharArray());
        assertTrue("Expected auto-activated CryptoToken to still be active.", cryptoTokenManagementSession.isCryptoTokenStatusActive(roleMgmgToken, cryptoTokenId));
    }

    @Test
    public void testIllegalCAKeyLengthRsa() throws Exception {
        try {
            CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testIllegalCAKeyLengthRsa", "512");
            fail("Shouldn't be able to generate CA keystore keys with 512 bit RSA");
        } catch (RuntimeException e) {
            assertEquals(InvalidKeyException.class.getName(), e.getCause().getClass().getName());
        }
    }

    @Test
    public void testIllegalCAKeyLengthDsa() throws Exception {
        try {
            CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testIllegalCAKeyLengthDsa", "DSA512");
            fail("Shouldn't be able to generate CA keystore keys with 512 bit DSA");
        } catch (RuntimeException e) {
            assertEquals(InvalidKeyException.class.getName(), e.getCause().getClass().getName());
        }
    }

    @Test
    public void testIllegalCAKeyLengthEcdsa() throws Exception {
        try {
            CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "testIllegalCAKeyLengthEcdsa", "prime192v1");
            fail("Shouldn't be able to generate CA keystore keys with 'prime192v1' ECDSA");
        } catch (RuntimeException e) {
            log.debug("", e);
            assertEquals(InvalidKeyException.class.getName(), e.getCause().getClass().getName());
        }
    }

    @Test
    public void modifyPin() throws Exception {
        final boolean UPDATE_ONLY = true;
        final boolean SET_ALWAYS = false;
        final char[] PIN_ORG = "foo1234".toCharArray();
        final char[] PIN_SECOND = "foo123".toCharArray();
        final char[] PIN_WRONG = "wrong".toCharArray();
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(roleMgmgToken, "modifyPin", "RSA1024");
            // Note the secondary testing of pin changes is the calls below
            final boolean usesAutoActivation1 = cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_ORG, PIN_SECOND, UPDATE_ONLY);
            assertTrue("Updating soft keystore pin should not remove auto activation", usesAutoActivation1);
            final boolean usesAutoActivation2 = cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_SECOND, PIN_ORG, SET_ALWAYS);
            assertTrue("Updating soft keystore pin should not remove auto activation", usesAutoActivation2);
            final boolean usesAutoActivation3 = cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_ORG, null, SET_ALWAYS);
            assertFalse("Auto activation should not be in use after removing 'auto activation pin'", usesAutoActivation3);
            final boolean usesAutoActivation4 = cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_ORG, PIN_SECOND, UPDATE_ONLY);
            assertFalse("Auto activation should not be in use when it was not before and we only update when present.", usesAutoActivation4);
            final boolean usesAutoActivation5 = cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_ORG, PIN_ORG, SET_ALWAYS);
            assertTrue("Auto activation should be in use when it was not before and we force it.", usesAutoActivation5);
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_WRONG, PIN_SECOND, UPDATE_ONLY);
                fail("It should not be possible to update a keystore pin using the wrong current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_WRONG, PIN_SECOND, SET_ALWAYS);
                fail("It should not be possible to update a keystore pin using the wrong current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_WRONG, null, UPDATE_ONLY);
                fail("It should not be possible to remove the auto-activation pin using the wrong current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, PIN_WRONG, null, SET_ALWAYS);
                fail("It should not be possible to remove the auto-activation pin using the wrong current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, null, PIN_SECOND, UPDATE_ONLY);
                fail("It should not be possible to update a keystore pin without the current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
            try {
                cryptoTokenManagementSession.updatePin(alwaysAllowToken, cryptoTokenId, null, PIN_SECOND, SET_ALWAYS);
                fail("It should not be possible to update a keystore pin without the current pin.");
            } catch (CryptoTokenAuthenticationFailedException e) {
                // Expected
            }
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(roleMgmgToken, cryptoTokenId);
        }
    }
    

    

   

   
}
