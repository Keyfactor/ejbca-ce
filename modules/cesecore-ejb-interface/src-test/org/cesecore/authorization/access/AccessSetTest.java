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
package org.cesecore.authorization.access;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 *
 * @version $Id$
 */
public final class AccessSetTest {

    private static final Logger log = Logger.getLogger(AccessSetTest.class);

    @SuppressWarnings("deprecation")
    private final AccessSet as = makeLegacyAccessSet("/test", "/one/two", "/three", "/three/four", "/three/four/five",
            "/six", "/six/" + AccessSet.WILDCARD_RECURSIVE, "/seven/eight", "/seven/eight/" + AccessSet.WILDCARD_RECURSIVE,
            "/nine/", "/ten/eleven/subresource", // currently unused
            "/twelve/" + AccessSet.WILDCARD_SOME, "/twelve/-123456",
            "/thirteen/" + AccessSet.WILDCARD_SOME + "/subres", "/thirteen/98765/subres");

    @Test
    public void testSimpleAllowed() {
        log.trace(">testSimpleAllowed");
        assertTrue(as.isAuthorized("/test"));
        assertTrue(as.isAuthorized("/three"));
        log.trace("<testSimpleAllowed");
    }

    @Test
    public void testSimpleDenied() {
        log.trace(">testSimpleDenied");
        assertFalse(as.isAuthorized("/"));
        assertFalse(as.isAuthorized("/nonexistent"));
        log.trace("<testSimpleDenied");
    }

    @Test
    public void testNested() {
        log.trace(">testNested");
        assertTrue(as.isAuthorized("/one/two"));
        assertTrue(as.isAuthorized("/three/four"));
        assertTrue(as.isAuthorized("/three/four/five"));
        assertFalse(as.isAuthorized("/one/notgranted"));
        assertFalse(as.isAuthorized("/three/five"));
        assertFalse(as.isAuthorized("/three/four/nine"));
        log.trace("<testNested");
    }

    @Test
    public void testRecursive() {
        log.trace(">testRecursive");
        assertTrue(as.isAuthorized("/six"));
        assertTrue(as.isAuthorized("/six/blabla"));
        assertTrue(as.isAuthorized("/six/-9876"));
        assertTrue(as.isAuthorized("/six/blabla/" + AccessSet.WILDCARD_SOME + "/bla"));
        assertTrue(as.isAuthorized("/six/blabla/123456/bla"));
        assertTrue(as.isAuthorized("/seven/eight"));
        assertTrue(as.isAuthorized("/seven/eight/test"));
        assertTrue(as.isAuthorized("/seven/eight/test/bla/bla/bla"));
        log.trace("<testRecursive");
    }

    @SuppressWarnings("deprecation")
    @Test
    public void testSlashRecurisve() {
        log.trace(">testSlashRecurisve");
        final AccessSet sr = makeLegacyAccessSet("/" + AccessSet.WILDCARD_RECURSIVE);
        assertTrue(sr.isAuthorized("/"));
        assertTrue(sr.isAuthorized("/one"));
        assertTrue(sr.isAuthorized("/one/two/three"));
        assertTrue(sr.isAuthorized("/one/-1234/three"));
        log.trace("<testSlashRecurisve");
    }

    @Test
    public void testSomeWilcard() {
        log.trace(">testSomeWilcard");
        assertTrue(as.isAuthorized("/twelve/" + AccessSet.WILDCARD_SOME));
        assertTrue(as.isAuthorized("/thirteen/" + AccessSet.WILDCARD_SOME + "/subres"));
        assertFalse(as.isAuthorized("/twelve/-11111"));
        assertFalse(as.isAuthorized("/thirteen/22222/subres"));
        log.trace("<testAllWilcard");
    }

    @Test
    public void testBadResources() {
        log.trace(">testBadResources");
        // The correct syntax is /bla/blabla
        try {
            as.isAuthorized("bla/blabla");
            fail("Should fail");
        } catch (IllegalArgumentException e) {
            // NOPMD expected
        }
        try {
            as.isAuthorized("/bla/blabla/");
            fail("Should fail");
        } catch (IllegalArgumentException e) {
            // NOPMD expected
        }
        log.trace("<testBadResources");
    }
    
    @Test
    public void testNewAccessMap() {
        log.trace(">testNewAccessMap");
        final AccessSet asNew = makeNewAccessSet();
        // The new access rule representation is a plain Map<String,Boolean> that is used with
        // AccessRulesHelper (which is tested in AccessRulesHelperTest). So let's only do basic testing here
        assertTrue(asNew.isAuthorized("/a/"));
        assertFalse(asNew.isAuthorized("/b/"));
        assertTrue(asNew.isAuthorized("/b/c/"));
        assertTrue(asNew.isAuthorized("/b/c/d/"));
        assertFalse(asNew.isAuthorized("/b/c/e/"));
        assertTrue(asNew.isAuthorized("/nonexistent"));
        log.trace("<testNewAccessMap");
    }
    
    @SuppressWarnings("deprecation")
    @Test
    public void testConvertAndMerge() {
        log.trace(">testConvertAndMerge");
        final AccessSet asNew = makeNewAccessSet();
        // Merge with an old AccessSet to force downgrade
        final AccessSet asOld = new AccessSet(Arrays.asList("/a", "/f", "/nonexistentold"));
        final AccessSet merged = new AccessSet(asNew, asOld);
        assertTrue(merged.isAuthorized("/a"));
        assertFalse(merged.isAuthorized("/b"));
        assertTrue(merged.isAuthorized("/b/c"));
        assertTrue(merged.isAuthorized("/b/c/d"));
        assertFalse(merged.isAuthorized("/b/c/e"));
        assertTrue(merged.isAuthorized("/f"));
        assertFalse(merged.isAuthorized("/nonexistent")); // the converter does not allow non-existent resources
        assertTrue(merged.isAuthorized("/nonexistentold")); // this rule comes from the old AccessSet, so it's left untouched
        log.trace("<testConvertAndMerge");
    }

    /** Creates an AccessSet with the legacy representation of access rules  */
    @SuppressWarnings("deprecation")
    private AccessSet makeLegacyAccessSet(final String... resources) {
        final Collection<String> col = new ArrayList<>();
        for (final String resource : resources) {
            col.add(resource);
        }
        return new AccessSet(col);
    }
    
    private AccessSet makeNewAccessSet() {
        final Set<String> allResources = new HashSet<>();
        allResources.add("/a/");
        allResources.add("/b/");
        allResources.add("/b/c/");
        allResources.add("/b/c/d/");
        allResources.add("/b/c/e/");
        allResources.add("/f/");
        final HashMap<String,Boolean> accessRules = new HashMap<>();
        accessRules.put("/a/", true);
        accessRules.put("/b/c/", true);
        accessRules.put("/b/c/e/", false);
        accessRules.put("/nonexistent/", true);
        return new AccessSet(accessRules, allResources);
    }

}
