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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests on methods in Role.
 * 
 * @version $Id$
 */
public class RoleUnitTest {

    private static final Logger log = Logger.getLogger(RoleUnitTest.class);
    private static final String ERRMSG_ALLOWED_TO_DENIED = "Access granted that should have been denied.";
    private static final String ERRMSG_DENIED_TO_ALLOWED = "Access denied that should have been granted.";

    private RoleDataDto roleData;

    @Before
    public void setUp() throws Exception {
        roleData = new RoleDataDtoBuilder()
                .setName("role")
                .build();
    }

    @Test
    public void testHasAccessToResource() {
        log.trace(">testHasAccessToResource");
        Map<String, Boolean> accessRules = new HashMap<>();
        accessRules.put("/fuu", RoleDataDto.STATE_ALLOW);
        accessRules.put("/foo/bar", RoleDataDto.STATE_DENY);
        accessRules.put("/xyz", RoleDataDto.STATE_DENY);
        accessRules.put("/xyz_abc", RoleDataDto.STATE_ALLOW);
        accessRules.put("/1/2/3/4", RoleDataDto.STATE_DENY);
        accessRules.put("/1", RoleDataDto.STATE_ALLOW);
        accessRules.put("/1/2", RoleDataDto.STATE_ALLOW);
        accessRules.put("/a/b/c/d", RoleDataDto.STATE_ALLOW);
        accessRules.put("/a/b", RoleDataDto.STATE_DENY);
        accessRules.put("/", RoleDataDto.STATE_DENY);
        roleData = roleData.withAccessRules(accessRules);
        debugLogAccessRules(roleData);
        hasAccessToResourcesInternal(roleData);
        debugLogAccessRules(roleData);
        hasAccessToResourcesInternal(roleData);
        roleData = roleData.withAccessRules(AccessRulesHelper.getMinimizedAccessRules(roleData.accessRules()));
        debugLogAccessRules(roleData);
        hasAccessToResourcesInternal(roleData);
        assertNull("Minimization did not remove deny rule.", roleData.accessRules().get("/xyz"));
        assertNull("Minimization did not remove allow rule.", roleData.accessRules().get("/1/2"));
        assertNull("Minimization did not remove top deny rule.", roleData.accessRules().get("/"));
        log.trace("<testHasAccessToResource");
    }
    
    private void hasAccessToResourcesInternal(final RoleDataDto roleData) {
        // Check explicitly configured access
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/foo/bar"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz_abc"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c/d"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3/4"));
        // Check implicitly configured access
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu/anything"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu/anything/something"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz/abc"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz_abc/foo"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c/d/e"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/f"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3/4/5"));
        // Check explicitly configured access (normalized form)
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/foo/bar/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz_abc/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c/d/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3/4/"));
        // Check implicitly configured access (normalized form)
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu/anything/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/fuu/anything/something/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz/abc/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/xyz_abc/foo/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c/d/e/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/c/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/b/f/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/a/"));
        assertTrue( ERRMSG_DENIED_TO_ALLOWED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3/"));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(roleData.accessRules(), "/1/2/3/4/5/"));
    }
    
    /** Make sure that access to root is never given by mistake. */
    @Test
    public void testNoDefaultAccessToRoot() {
        log.trace(">testNoDefaultAccessToRoot");
        // Given
        final RoleDataDto role = new RoleDataDtoBuilder()
                .setName("role")
                .build()
                .withAccessRules(Map.of("/fuu", RoleDataDto.STATE_ALLOW));
        assertFalse(ERRMSG_ALLOWED_TO_DENIED, AccessRulesHelper.hasAccessToResource(role.accessRules(), "/"));
        log.trace("<testNoDefaultAccessToRoot");
    }

    private void debugLogAccessRules(final RoleDataDto roleData) {
        log.debug("Role: " + roleData.fullName());
        final List<Entry<String, Boolean>> accessRulesList = AccessRulesHelper.getAsListSortedByKey(roleData.accessRules());
        for (final Entry<String,Boolean> entry : accessRulesList) {
            log.debug(" " + entry.getKey() + ":" + (entry.getValue().booleanValue()?"allow":"deny"));
        }
    }

}
