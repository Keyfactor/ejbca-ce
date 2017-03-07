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
package org.cesecore.roles;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test helper for operations on the access rules.
 * 
 * @version $Id$
 */
public class AccessRulesHelperTest {

    private static final Logger log = Logger.getLogger(AccessRulesHelperTest.class);
    private static final String ERRMSG_ALLOWED_TO_DENIED = "Access granted that should have been denied.";
    private static final String ERRMSG_DENIED_TO_ALLOWED = "Access denied that should have been granted.";
    private static final String ERRMSG_UNEXPECTED_STATE = "Unexptected state of access rule.";

    @Test
    public void testUnion() {
        log.trace(">testUnion");
        final HashMap<String, Boolean> accessRules1 = new HashMap<>();
        accessRules1.put("/a/", Role.STATE_ALLOW);
        accessRules1.put("/a/b/", Role.STATE_DENY);
        accessRules1.put("/b/", Role.STATE_DENY);
        accessRules1.put("/b/a/", Role.STATE_ALLOW);
        final HashMap<String, Boolean> accessRules2 = new HashMap<>();
        accessRules2.put("/a/", Role.STATE_ALLOW);
        accessRules2.put("/a/c/", Role.STATE_DENY);
        accessRules2.put("/c/", Role.STATE_ALLOW);
        accessRules2.put("/c/d/", Role.STATE_DENY);
        testUnion(accessRules1, accessRules2);
        testUnion(accessRules2, accessRules1);
        log.trace("<testUnion");
    }

    private void testUnion(final HashMap<String, Boolean> accessRules1, final HashMap<String, Boolean> accessRules2) {
        log.trace(" accessRules1:");
        debugLogAccessRules(accessRules1);
        log.trace(" accessRules2:");
        debugLogAccessRules(accessRules2);
        final HashMap<String, Boolean> accessRules = AccessRulesHelper.getAccessRulesUnion(accessRules1, accessRules2);
        log.trace("  after union of rules:");
        debugLogAccessRules(accessRules);
        // Verify that the expected input rules are present in normalized form
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_ALLOW, accessRules.get("/a/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/a/b/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/a/c/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/b/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_ALLOW, accessRules.get("/b/a/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_ALLOW, accessRules.get("/c/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_DENY,  accessRules.get("/c/d/"));
        // Verify that no other rules are present
        final HashMap<String, Boolean> accessRulesToClean = new HashMap<>(accessRules);
        accessRulesToClean.remove("/a/");
        accessRulesToClean.remove("/b/a/");
        accessRulesToClean.remove("/c/");
        accessRulesToClean.remove("/c/d/");
        log.trace(" after removal of all expected rules:");
        debugLogAccessRules(accessRulesToClean);
        assertTrue("Unexpected rules are present after union.", accessRulesToClean.isEmpty());
        // Verify that the merged rules gives the expected access
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/b/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/c/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/b/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/b/a/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/c/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/c/d/"));
    }

    @Test
    public void testIntersection() {
        log.trace(">testIntersection");
        final HashMap<String, Boolean> accessRules1 = new HashMap<>();
        accessRules1.put("/a/", Role.STATE_ALLOW);
        accessRules1.put("/a/b/", Role.STATE_DENY);
        accessRules1.put("/b/", Role.STATE_DENY);
        accessRules1.put("/b/a/", Role.STATE_ALLOW);
        accessRules1.put("/b/b/", Role.STATE_ALLOW);
        accessRules1.put("/c/d/", Role.STATE_ALLOW);
        final HashMap<String, Boolean> accessRules2 = new HashMap<>();
        accessRules2.put("/a/", Role.STATE_ALLOW);
        accessRules2.put("/a/c/", Role.STATE_DENY);
        accessRules2.put("/b/b/", Role.STATE_ALLOW);
        accessRules2.put("/c/", Role.STATE_ALLOW);
        accessRules2.put("/c/d/", Role.STATE_DENY);
        testIntersection(accessRules1, accessRules2);
        testIntersection(accessRules2, accessRules1);
        log.trace("<testIntersection");
    }

    private void testIntersection(final HashMap<String, Boolean> accessRules1, final HashMap<String, Boolean> accessRules2) {
        log.trace(" accessRules1:");
        debugLogAccessRules(accessRules1);
        log.trace(" accessRules2:");
        debugLogAccessRules(accessRules2);
        final HashMap<String, Boolean> accessRules = AccessRulesHelper.getAccessRulesIntersection(accessRules1, accessRules2);
        log.trace(" after intersection of rules:");
        debugLogAccessRules(accessRules);
        // Verify that the expected input rules are present in normalized form
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_ALLOW, accessRules.get("/a/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_DENY,  accessRules.get("/a/b/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_DENY,  accessRules.get("/a/c/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/b/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/b/a/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, Role.STATE_ALLOW, accessRules.get("/b/b/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/c/"));
        assertEquals(ERRMSG_UNEXPECTED_STATE, null,             accessRules.get("/c/d/"));
        // Verify that no other rules are present
        final HashMap<String, Boolean> accessRulesToClean = new HashMap<>(accessRules);
        accessRulesToClean.remove("/a/");
        accessRulesToClean.remove("/a/b/");
        accessRulesToClean.remove("/a/c/");
        accessRulesToClean.remove("/b/b/");
        log.trace(" after removal of all expected rules:");
        debugLogAccessRules(accessRulesToClean);
        assertTrue("Unexpected rules are present after intersection.", accessRulesToClean.isEmpty());
        // Verify that the merged rules gives the expected access
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/b/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/a/c/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/b/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/b/a/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(accessRules, "/b/b/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/c/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(accessRules, "/c/d/"));
    }

    @Test
    public void testSorting() {
        final LinkedHashMap<String, Boolean> accessRules = new LinkedHashMap<>();
        accessRules.put("/abc/d/", Role.STATE_ALLOW);
        accessRules.put("/abc/", Role.STATE_DENY);
        accessRules.put("/", Role.STATE_ALLOW);
        accessRules.put("/a/b/", Role.STATE_DENY);
        accessRules.put("/a/", Role.STATE_ALLOW);
        AccessRulesHelper.sortAccessRules(accessRules);
        final Iterator<Entry<String, Boolean>> iterator = accessRules.entrySet().iterator();
        assertEquals("/", iterator.next().getKey());
        assertEquals("/a/", iterator.next().getKey());
        assertEquals("/a/b/", iterator.next().getKey());
        assertEquals("/abc/", iterator.next().getKey());
        assertEquals("/abc/d/", iterator.next().getKey());
    }

    private void debugLogAccessRules(final HashMap<String, Boolean> accessRules) {
        final List<Entry<String, Boolean>> accessRulesList = AccessRulesHelper.getAsListSortedByKey(accessRules);
        for (final Entry<String,Boolean> entry : accessRulesList) {
            log.debug(" " + entry.getKey() + ":" + (entry.getValue().booleanValue()?"allow":"deny"));
        }
    }
}
