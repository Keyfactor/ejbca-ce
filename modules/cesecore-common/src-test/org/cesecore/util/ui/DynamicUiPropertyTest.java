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
package org.cesecore.util.ui;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.cesecore.roles.AdminGroupData;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class DynamicUiPropertyTest {

    @Test
    public void testEncodingAndDecodingOfComplexType() throws PropertyValidationException {
        AdminGroupData anybody = new AdminGroupData(-1, "anybody");
        DynamicUiProperty<AdminGroupData> roleProperty = new DynamicUiProperty<AdminGroupData>("test",
                anybody, new HashSet<AdminGroupData>(Arrays.asList(anybody)));
        roleProperty.setHasMultipleValues(true);
        List<String> encodedValues = roleProperty.getEncodedValues();
       
        DynamicUiProperty<AdminGroupData> rolePropertyCopy = new DynamicUiProperty<AdminGroupData>("test",
                anybody, new HashSet<AdminGroupData>());
        rolePropertyCopy.setHasMultipleValues(true);
        rolePropertyCopy.setEncodedValues(encodedValues);
        assertTrue("RoleData object didn't survive encodement/decodement", rolePropertyCopy.getValues().contains(anybody));
        
    }
}
