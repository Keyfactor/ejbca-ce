/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import static org.junit.Assert.assertTrue;

import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class AccessUserAspectDataTest {

    @Test
    public void testGeneratePrimaryKeyWhereRoleNameAndMatchValueAreTheSame() {
        int alpha = AccessUserAspectData.generatePrimaryKey("foo", 1337, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "bar1");
        int beta = AccessUserAspectData.generatePrimaryKey("foo", 1337, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "bar2");
        assertTrue("Two identical primary keys were produced for different values", alpha != beta);
    }
    
    @Test
    public void testGeneratePrimaryKeyWhereRoleNameAndMatchValueAreSwitched() {
        int alpha = AccessUserAspectData.generatePrimaryKey("foo", 1337, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "bar");
        int beta = AccessUserAspectData.generatePrimaryKey("bar", 1337, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "foo");
        assertTrue("Two identical primary keys were produced for different values", alpha != beta);
    }

}
