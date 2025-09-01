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
package org.cesecore.authorization.user;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Unit tests for the AccessMatchType enums.
 * 
 *
 */
public class AccessMatchTypeUnitTest {

    @Test
    public void testAccessMatchEnum() throws SecurityException {
        AccessMatchType type0 = AccessMatchType.matchFromDatabase(0);
        AccessMatchType type1000 = AccessMatchType.matchFromDatabase(1000);
        AccessMatchType type1001 = AccessMatchType.matchFromDatabase(1001);
        assertEquals("name is incorrect", "TYPE_UNUSED", type0.name());
        assertEquals("name is incorrect", "TYPE_EQUALCASE", type1000.name());
        assertEquals("name is incorrect", "TYPE_EQUALCASEINS", type1001.name());
    }
}
