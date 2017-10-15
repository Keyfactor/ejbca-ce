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
 * @version $Id$
 *
 */
public class AccessMatchTypeTest {

    @Test
    public void testAccessMatchEnum() throws SecurityException {
        AccessMatchType type0 = AccessMatchType.matchFromDatabase(0);
        AccessMatchType type1000 = AccessMatchType.matchFromDatabase(1000);
        AccessMatchType type1001 = AccessMatchType.matchFromDatabase(1001);
        AccessMatchType type1002 = AccessMatchType.matchFromDatabase(1002);
        AccessMatchType type1003 = AccessMatchType.matchFromDatabase(1003);
        AccessMatchType type1999 = AccessMatchType.matchFromDatabase(1999);
        AccessMatchType type2000 = AccessMatchType.matchFromDatabase(2000);
        AccessMatchType type2001 = AccessMatchType.matchFromDatabase(2001);
        AccessMatchType type2002 = AccessMatchType.matchFromDatabase(2002);
        AccessMatchType type2003 = AccessMatchType.matchFromDatabase(2003);
        AccessMatchType type2004 = AccessMatchType.matchFromDatabase(2004);
        AccessMatchType type2005 = AccessMatchType.matchFromDatabase(2005);
        assertEquals("name is incorrect", "TYPE_UNUSED", type0.name());
        assertEquals("name is incorrect", "TYPE_EQUALCASE", type1000.name());
        assertEquals("name is incorrect", "TYPE_EQUALCASEINS", type1001.name());
        // Types before the role rewrite in EJBCA 6.9, must be kept for upgrade reasons, 
        // these types are bound to be hanging around in the database
        assertEquals("name is incorrect", "TYPE_NOT_EQUALCASE", type1002.name());
        assertEquals("name is incorrect", "TYPE_NOT_EQUALCASEINS", type1003.name());
        assertEquals("name is incorrect", "TYPE_NONE", type1999.name());
        // Types that were used earlier than EJBCA 4, must also be kept for upgrade reasons,
        // since we support 100% uptime upgrades, we can not NPE if these are in the database
        assertEquals("name is incorrect", "SPECIALADMIN_PUBLICWEBUSER", type2000.name());
        assertEquals("name is incorrect", "SPECIALADMIN_CACOMMANDLINEADMIN", type2001.name());
        assertEquals("name is incorrect", "SPECIALADMIN_RAADMIN", type2002.name());
        assertEquals("name is incorrect", "SPECIALADMIN_BATCHCOMMANDLINEADMIN", type2003.name());
        assertEquals("name is incorrect", "SPECIALADMIN_INTERNALUSER", type2004.name());
        assertEquals("name is incorrect", "SPECIALADMIN_NOUSER", type2005.name());
    }

}
