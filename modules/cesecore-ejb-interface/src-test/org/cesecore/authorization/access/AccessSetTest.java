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
import java.util.Collection;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * 
 * @version $Id$
 */
public final class AccessSetTest {
    
    private static final Logger log = Logger.getLogger(AccessSetTest.class);
    
    private final AccessSet as = makeAccessSet("/test", "/one/two", "/three", "/three/four", "/three/four/five",
            "/six", "/six/" + AccessSets.WILDCARD_RECURSIVE, "/seven/eight", "/seven/eight/" + AccessSets.WILDCARD_RECURSIVE,
            "/nine/" + AccessSets.WILDCARD_ALL, "/ten/eleven/" + AccessSets.WILDCARD_ALL + "/subresource",
            "/twelve/" + AccessSets.WILDCARD_SOME, "/twelve/-123456",
            "/thirteen/" + AccessSets.WILDCARD_SOME + "/subres", "/thirteen/98765/subres");

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
        assertTrue(as.isAuthorized("/six/blabla/" + AccessSets.WILDCARD_SOME + "/bla"));
        assertTrue(as.isAuthorized("/six/blabla/123456/bla"));
        assertTrue(as.isAuthorized("/seven/eight"));
        assertTrue(as.isAuthorized("/seven/eight/test"));
        assertTrue(as.isAuthorized("/seven/eight/test/bla/bla/bla"));
        log.trace("<testRecursive");
    }
    
    @Test
    public void testSlashRecurisve() {
        log.trace(">testSlashRecurisve");
        final AccessSet sr = makeAccessSet("/" + AccessSets.WILDCARD_RECURSIVE);
        assertTrue(sr.isAuthorized("/"));
        assertTrue(sr.isAuthorized("/one"));
        assertTrue(sr.isAuthorized("/one/two/three"));
        assertTrue(sr.isAuthorized("/one/-1234/three"));
        log.trace("<testSlashRecurisve");
    }
    
    @Test
    public void testAllWilcard() {
        log.trace(">testAllWilcard");
        assertTrue(as.isAuthorized("/nine/12345"));
        assertTrue(as.isAuthorized("/nine/-12345678"));
        assertTrue(as.isAuthorized("/ten/eleven/12345/subresource"));
        assertTrue(as.isAuthorized("/ten/eleven/-12345678/subresource"));
        assertFalse(as.isAuthorized("/nine"));
        assertFalse(as.isAuthorized("/nine/notanumber"));
        assertFalse(as.isAuthorized("/nine/notanumber/xyz"));
        assertFalse(as.isAuthorized("/nine/45678/notgranted"));
        log.trace("<testAllWilcard");
    }
    
    @Test
    public void testSomeWilcard() {
        log.trace(">testSomeWilcard");
        assertTrue(as.isAuthorized("/twelve/" + AccessSets.WILDCARD_SOME));
        assertTrue(as.isAuthorized("/thirteen/" + AccessSets.WILDCARD_SOME + "/subres"));
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
    
    private AccessSet makeAccessSet(final String... resources) {
        final Collection<String> col = new ArrayList<>();
        for (final String resource : resources) {
            col.add(resource);
        }
        return new AccessSet(col);
    }
    
}
