/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.authorization;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class DefaultRolesTest {
    
    @Test
    public void testEquals() {
        String roleName = DefaultRoles.SUPERADMINISTRATOR.getName();
        assertTrue(DefaultRoles.SUPERADMINISTRATOR.equals(roleName));
    }

}
