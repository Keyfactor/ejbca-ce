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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Unit tests for ExternalScriptsWhitelist.
 * @version $Id$
 */
public class ExternalScriptsWhitelistTest {
    @Test
    public void testConstructionFromText() {
        final ExternalScriptsWhitelist whitelist = ExternalScriptsWhitelist.fromText("/foo/allowed\n#/foo/disabled");
        assertEquals(1, whitelist.size());
        assertTrue("/foo/allowed should be permitted", whitelist.isPermitted("/foo/allowed"));
        assertFalse("/foo/forbidden should not be permitted", whitelist.isPermitted("/foo/forbidden"));
        assertFalse("Extension should be considered", whitelist.isPermitted("/foo/allowed.sh"));
        assertFalse("Directory path should be considered", whitelist.isPermitted("/usr/bin/allowed"));
        assertFalse("Command which is commented out should not be on whitelist", whitelist.isPermitted("/foo/disabled"));
        assertFalse("Command which is commented out should not be on whitelist", whitelist.isPermitted("#/foo/disabled"));
    }

    @Test
    public void testConstructionFromPaths() {
        final ExternalScriptsWhitelist whitelist = new ExternalScriptsWhitelist("/foo/allowed");
        assertEquals(1, whitelist.size());
        assertTrue("/foo/allowed should be permitted", whitelist.isPermitted("/foo/allowed"));
        assertFalse("/foo/forbidden should not be permitted", whitelist.isPermitted("/foo/forbidden"));
        assertFalse("Extension should be considered", whitelist.isPermitted("/foo/allowed.sh"));
        assertFalse("Directory path should be considered", whitelist.isPermitted("/usr/bin/allowed"));
    }

    @Test
    public void testPermitAll() {
        final ExternalScriptsWhitelist whitelist = ExternalScriptsWhitelist.permitAll();
        assertEquals(0, whitelist.size());
        assertTrue("/foo/allowed should be permitted", whitelist.isPermitted("/foo/allowed"));
    }

    @Test
    public void testInvalidPaths() {
        final ExternalScriptsWhitelist whitelist = new ExternalScriptsWhitelist("/foo/invalid");
        assertEquals(1, whitelist.size());
        assertTrue("/foo/invalid should not be a valid path", whitelist.hasInvalidPaths());
    }
}
