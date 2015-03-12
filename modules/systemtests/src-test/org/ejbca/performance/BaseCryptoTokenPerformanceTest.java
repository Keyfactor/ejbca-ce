/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.performance;

import java.util.Properties;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.ejbca.performance.legacy.LegacySoftCryptoToken;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
@Ignore //Set to ignore as to not be run on a regular basis
public class BaseCryptoTokenPerformanceTest {
    
    /**
     * Most granial performance test, will initialize a single SoftCryptoToken and repeatedly request keys. Will compare an archived version with the latest version
     * in the code tree.
     * @throws Exception 
     */
    @Test
    public void performMultipleKeyRetrieval() throws Exception {
        
        
        LegacySoftCryptoToken legacyToken = new LegacySoftCryptoToken();
       
        testCryptoToken("Legacy BaseCryptoToken", legacyToken);
        ConfigurationHolder.updateConfiguration("cryptotoken.keystorecache", "false");  
        SoftCryptoToken uncachingToken = new SoftCryptoToken();
        testCryptoToken("New CryptoToken without caching", uncachingToken);
        ConfigurationHolder.updateConfiguration("cryptotoken.keystorecache", "true");
        SoftCryptoToken cachingToken = new SoftCryptoToken();
        testCryptoToken("New CryptoToken without caching", cachingToken);
    }

    private long testCryptoToken(String name, CryptoToken cryptoToken) throws Exception {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foo123");
        cryptoToken.init(cryptoTokenProperties, null, 1);
        cryptoToken.generateKeyPair("512", CAToken.SOFTPRIVATESIGNKEYALIAS);
        long timeBefore = System.currentTimeMillis();
        long times = 100000000;
        for (int i = 0; i < times; ++i) {
            cryptoToken.getPublicKey(CAToken.SOFTPRIVATESIGNKEYALIAS);
        }
        long timeAfter = System.currentTimeMillis();
        long timeTotal = timeAfter - timeBefore;
        System.err.println("Retrieved PublicKey for: " + name + " " + times + " times in " + timeTotal + "ms.");
        System.err.println("Average time: " + times/timeTotal + " retrievals per ms");
        return timeTotal;
    }
    
}
