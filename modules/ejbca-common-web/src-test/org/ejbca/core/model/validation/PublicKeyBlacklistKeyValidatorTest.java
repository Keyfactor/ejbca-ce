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

/**
 * Test class fot public key blacklist key validator functional methods.
 * 
 * @version $Id$
 */
package org.ejbca.core.model.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.keys.validation.ValidatorBase;
import org.ejbca.core.ejb.ca.validation.BlacklistData;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Tests public key blacklist key validator functions.
 * 
 * @version $Id$
 */
public class PublicKeyBlacklistKeyValidatorTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistKeyValidatorTest.class);

    @BeforeClass
    public static void setClassUp() throws Exception {
        log.trace("setClassUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("setClassUp()");
    }

    @Test
    public void testMatchBlacklistedPublicKeyRSA() throws Exception {
        log.trace(">testMatchBlacklistedPublicKeyRSA()");

        KeyPair keyPair = KeyTools.genKeys("1024", "RSA");

        // A: Test public key blacklist validation OK with empty blacklist.        
        PublicKeyBlacklistKeyValidator keyValidator = createKeyValidator("publickey-blacklist-validation-test-1",
                "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setUseOnlyCache(true); // don't try to make EJB lookup for the "real" blacklist
        //        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        List<String> messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertTrue("Key valildation should have been successful.", messages.size() == 0);

        // B: Test public key blacklist validation NOK with match.
        List<String> algorithms = new ArrayList<String>();
        algorithms.add("-1");
        keyValidator.setKeyAlgorithms(algorithms);
        {
            // Manual update of cache entry
            final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint(keyPair.getPublic());
            BlacklistData data = new BlacklistData(entry);
            PublicKeyBlacklistEntryCache.INSTANCE.updateWith(123, data.getProtectString(0).hashCode(), entry.getFingerprint(), entry);
        }
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have failed because of public key fingerprint match.", 1, messages.size());

        // B-1: Test public key blacklist validation OK with match but other algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_DSA);
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have been successful because of public key fingerprint match but other algorithm.", 0, messages.size());

        // B-2: Test public key blacklist validation NOK with match and specified matching algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_RSA);
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have failed because of public key fingerprint match.", 1, messages.size());

        log.trace("<testMatchBlacklistedPublicKeyRSA()");
    }

    @Test
    public void testMatchBlacklistedPublicKeyEC() throws Exception {
        KeyPair keyPair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        // Test public key blacklist validation OK with empty blacklist.        
        PublicKeyBlacklistKeyValidator keyValidator = createKeyValidator("publickey-blacklist-validation-test-1",
                "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setUseOnlyCache(true); // don't try to make EJB lookup for the "real" blacklist           
        // B: Test public key blacklist validation NOK with match.
        List<String> algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_ECDSA);
        keyValidator.setKeyAlgorithms(algorithms);
        {
            // Manual update of cache entry
            final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint(keyPair.getPublic());
            BlacklistData data = new BlacklistData(entry);
            PublicKeyBlacklistEntryCache.INSTANCE.updateWith(123, data.getProtectString(0).hashCode(), entry.getFingerprint(), entry);
        }
        List<String> messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have failed because of public key fingerprint match.", 1, messages.size());
        
        // B-1: Test public key blacklist validation OK with match but other algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_DSA);
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have been successful because of public key fingerprint match but other algorithm.", 0, messages.size());

        // B-2: Test public key blacklist validation NOK with match and specified matching algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_EC);
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have failed because of public key fingerprint match.", 1, messages.size());
        // B-3: Test public key blacklist validation NOK with match and specified matching algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add(AlgorithmConstants.KEYALGORITHM_ECDSA);
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key valildation should have failed because of public key fingerprint match.", 1, messages.size());

    }
    /**
     * Same as testMatchBlacklistedPublicKeyEC, but specifies he algorithm as ECDSA instead of EC
     */
    @Test
    public void testMatchBlacklistedPublicKeyECDSA() throws Exception {
        log.trace(">testMatchBlacklistedPublicKeyECDSA()");

        KeyPair keyPair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        // A: Test public key blacklist validation OK with empty blacklist.        
        PublicKeyBlacklistKeyValidator keyValidator = createKeyValidator("publickey-blacklist-validation-test-1",
                "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setUseOnlyCache(true); // don't try to make EJB lookup for the "real" blacklist
        //        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        List<String> messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertTrue("Key valildation should have been successful.", messages.size() == 0);

        // B: Test public key blacklist validation NOK with match.
        List<String> algorithms = new ArrayList<String>();
        algorithms.add("-1");
        keyValidator.setKeyAlgorithms(algorithms);
        {
            // Manual update of cache entry
            final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint(keyPair.getPublic());
            BlacklistData data = new BlacklistData(entry);
            PublicKeyBlacklistEntryCache.INSTANCE.updateWith(123, data.getProtectString(0).hashCode(), entry.getFingerprint(), entry);
        }
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertTrue("Key valildation should have failed because of public key fingerprint match.",
                messages.size() == 1);

        // B-1: Test public key blacklist validation OK with match but other algorithm.
        algorithms = new ArrayList<String>();
        algorithms.add("RSA");
        keyValidator.setKeyAlgorithms(algorithms);
        messages = keyValidator.validate(keyPair.getPublic(), null);
        log.trace("Key validation error messages: " + messages);
        assertTrue("Key valildation should have been successful because of public key fingerprint match but other algorithm.",
                messages.size() == 0);
        
        log.trace("<testMatchBlacklistedPublicKeyECDSA()");
    }

    /**
     * Factory method to create key validators.
     * 
     * @param type the key validator type (see {@link ValidatorBase#KEY_VALIDATOR_TYPE}
     * @param name the logical name
     * @param description the description text
     * @param notBefore the certificates validity not before
     * @param notBeforeCondition the certificates validity not before condition
     * @param notAfter the certificates validity not after
     * @param notAfterCondition the certificates validity not after condition
     * @param failedAction the failed action to be performed.
     * @param certificateProfileIds list of IDs of certificate profile to be applied to. 
     * @return the concrete key validator instance.
     */
    private PublicKeyBlacklistKeyValidator createKeyValidator(final String name, final String description, final Date notBefore,
            final int notBeforeCondition, final Date notAfter, final int notAfterCondition, final int failedAction,
            final Integer... certificateProfileIds) {
        PublicKeyBlacklistKeyValidator result = new PublicKeyBlacklistKeyValidator(name);
        if (null != description) {
            result.setDescription(description);
        }
        if (null != notBefore) {
            result.setNotBefore(notBefore);
        }
        if (-1 < notBeforeCondition) {
            result.setNotBeforeCondition(notBeforeCondition);
        }
        if (null != notAfter) {
            result.setNotAfter(notAfter);
        }
        if (-1 < notAfterCondition) {
            result.setNotAfterCondition(notAfterCondition);
        }
        if (-1 < failedAction) {
            result.setFailedAction(failedAction);
        }
        final List<Integer> ids = new ArrayList<Integer>();
        for (Integer id : certificateProfileIds) {
            ids.add(id);
        }
        result.setCertificateProfileIds(ids);
        return result;
    }

}
