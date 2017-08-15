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

package org.ejbca.core.ejb.ca.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.validation.BlacklistEntry;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Public Key Blacklist session.
 * 
 * @version $Id$
 */
public class BlacklistEntrySessionTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(BlacklistEntrySessionTest.class);

    /** Test user. */
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("PublicKeyBlacklistSessionTest-Admin"));

    private BlacklistSessionRemote listSession = EjbRemoteHelper.INSTANCE.getRemoteSession(BlacklistSessionRemote.class);


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
            assertNull("foo should not return an entry", listSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "foo"));
            Map<Integer, String> map = listSession.getBlacklistEntryIdToValueMap();
            int initialSize = map.size(); // perhaps we run this test on a system that has some data so we can not assume 0
            PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint("abc123");
            listSession.addBlacklistEntry(internalAdmin, entry);
            map = listSession.getBlacklistEntryIdToValueMap();
            int newSize = map.size(); // perhaps we run this test on a system that has some data so we can not assume 0
            assertEquals("map size should be increased", initialSize+1, newSize);
            assertNull("foo should not return an entry", listSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "foo"));
            map = listSession.getBlacklistEntryIdToValueMap();
            assertEquals("map should contain a new entry", initialSize+1, map.size());
            BlacklistEntry entry1 = listSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "abc123");
            assertNotNull("an entry should have been returned as we just added it", entry1);
            assertEquals("the map entry should have the same fingerprint as we added", "abc123", map.get(entry1.getID()));
            assertEquals("entry should have the fingerprint added, abc123", "abc123", entry1.getValue());
            listSession.removeBlacklistEntry(internalAdmin, PublicKeyBlacklistEntry.TYPE, "abc123");
            map = listSession.getBlacklistEntryIdToValueMap();
            assertEquals("map should contain one less entry", initialSize, map.size());
            assertNull("abc123 should not return an entry any longer", listSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "abc123"));
        } finally {
            try {
            listSession.removeBlacklistEntry(internalAdmin, PublicKeyBlacklistEntry.TYPE, "abc123");
            } catch (BlacklistDoesntExistsException e) {
                // NOOMD: do nothing
            }
        }
        log.trace("<testAddGetChangeRemove()");
    }

}
