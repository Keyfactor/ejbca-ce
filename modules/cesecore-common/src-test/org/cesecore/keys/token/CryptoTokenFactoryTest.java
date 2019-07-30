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
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests crypto token manager
 * 
 * @version $Id$
 */
public class CryptoTokenFactoryTest {

    private static final Logger log = Logger.getLogger(CryptoTokenFactoryTest.class);

    private static int numBuiltinCryptoTokenTypes;

    @BeforeClass
    public static void beforeClass() {
        try {
            Class.forName("org.cesecore.keys.token.p11ng.cryptotoken.JackNJI11CryptoToken");
            log.debug("Assuming we are running Enterprise Edition");
            numBuiltinCryptoTokenTypes = 5;
        } catch (ClassNotFoundException e) {
            log.debug("Assuming we are running Community Edition");
            numBuiltinCryptoTokenTypes = 4;
        }
    }

	@Test
	public void testAvailableCryptoToken() throws Exception {
	    log.trace(">testAvailableCryptoToken");
		CryptoTokenFactory mgr = CryptoTokenFactory.instance();
		Collection<AvailableCryptoToken> tokens = mgr.getAvailableCryptoTokens();
		assertEquals(numBuiltinCryptoTokenTypes, tokens.size());
		AvailableCryptoToken token1 = new AvailableCryptoToken(SoftCryptoToken.class.getName(), "SOFT", true, true);
		AvailableCryptoToken token2 = new AvailableCryptoToken(PKCS11CryptoToken.class.getName(), "PKCS#11", true, true);
		AvailableCryptoToken token3 = new AvailableCryptoToken(NullCryptoToken.class.getName(), "Null", true, true);
		// A token with the same classpath but different name should count as the same
		AvailableCryptoToken token4 = new AvailableCryptoToken(SoftCryptoToken.class.getName(), "FOO", true, true);
		// A token that should not exist, but with a real classpath
		AvailableCryptoToken token5 = new AvailableCryptoToken(MockCryptoToken.class.getName(), "FOO", true, true);
		// A token that should not exist, with a non existing classpath
		AvailableCryptoToken token6 = new AvailableCryptoToken("foo.bar.CryptoToken", "FOO", true, true);
		assertTrue(tokens.contains(token1));
		assertTrue(tokens.contains(token2));
		assertTrue(tokens.contains(token3));
		assertTrue(tokens.contains(token4));
		assertFalse(tokens.contains(token5));
		assertFalse(tokens.contains(token6));
		// Add the missing tokens
		mgr.addAvailableCryptoToken(MockCryptoToken.class.getCanonicalName(), "FOO", true, true);
		// The one with non existing classpath should not be added
		mgr.addAvailableCryptoToken("foo.bar.CryptoToken", "FOO", true, true);
		tokens = mgr.getAvailableCryptoTokens();
		assertEquals(numBuiltinCryptoTokenTypes+1, tokens.size());
		assertTrue(tokens.contains(token1));
		assertTrue(tokens.contains(token2));
		assertTrue(tokens.contains(token3));
		assertTrue(tokens.contains(token4));
		assertTrue(tokens.contains(token5));
		// The one with non existing classpath should not be added
		assertFalse(tokens.contains(token6));
		log.trace("<testAvailableCryptoToken");
	}

}


