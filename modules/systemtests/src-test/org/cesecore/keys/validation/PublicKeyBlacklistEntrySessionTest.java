/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Key validator session.
 * 
 * @version $Id: KeyValidatorSessionTest.java 25500 2017-04-01 11:28:08Z anjakobs $
 */
public class PublicKeyBlacklistEntrySessionTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistEntrySessionTest.class);

    /** Test user. */
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("PublicKeyBlacklistSessionTest-Admin"));

    private PublicKeyBlacklistSessionRemote listSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublicKeyBlacklistSessionRemote.class);


    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        log.trace("<tearDown()");
    }

    @Test
    public void testAddGetChangeRemove() throws Exception {
        log.trace(">testAddGetChangeRemove()");
        try {
            assertNull("foo should not return an entry", listSession.getPublicKeyBlacklistEntry("foo"));
            Map<Integer, String> map = listSession.getPublicKeyBlacklistEntryIdToFingerprintMap();
            int initialSize = map.size(); // perhaps we run this test on a system that has some data so we can not assume 0
            assertTrue("initial map should be empty", map.isEmpty());
            PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint("abc123");
            listSession.addPublicKeyBlacklistEntry(internalAdmin, entry);
            assertNull("foo should not return an entry", listSession.getPublicKeyBlacklistEntry("foo"));
            map = listSession.getPublicKeyBlacklistEntryIdToFingerprintMap();
            assertEquals("map should contain a new entry", initialSize+1, map.size());
            PublicKeyBlacklistEntry entry1 = listSession.getPublicKeyBlacklistEntry("abc123");
            assertNotNull("an entry should have been returned as we just added it", entry1);
            assertEquals("the map entry should have the same fingerprint as we added", "abc123", map.get(entry1.getID()));
            assertEquals("entry should have the fingerprint added, abc123", "abc123", entry1.getFingerprint());
            listSession.removePublicKeyBlacklistEntry(internalAdmin, "abc123");
            map = listSession.getPublicKeyBlacklistEntryIdToFingerprintMap();
            assertEquals("map should contain one less entry", initialSize, map.size());
            assertNull("abc123 should not return an entry any longer", listSession.getPublicKeyBlacklistEntry("abc123"));
        } finally {
            listSession.removePublicKeyBlacklistEntry(internalAdmin, "abc123");
        }
        log.trace("<testAddGetChangeRemove()");
    }

}
