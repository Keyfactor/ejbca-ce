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
package org.ejbca.core.model.ra.raadmin;

import static org.junit.Assert.assertFalse;

import java.util.Map;

import org.cesecore.certificates.util.DnComponents;
import org.junit.Test;

/**
 * Unit tests for the EndEntityProfile class.
 * 
 * @version $Id$
 *
 */
public class EndEntityProfileTest {

    @Test
    public void testEndEntityProfileDiff() {
        EndEntityProfile foo = new EndEntityProfile();
        EndEntityProfile bar = new EndEntityProfile();
        bar.addField(DnComponents.ORGANIZATIONUNIT);
        Map<Object, Object> diff = foo.diff(bar);
        assertFalse(diff.isEmpty());
    }
    
}
