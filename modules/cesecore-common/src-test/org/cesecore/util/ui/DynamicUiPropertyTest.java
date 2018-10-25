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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.cesecore.roles.Role;
import org.cesecore.roles.RoleData;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class DynamicUiPropertyTest {

    @Test
    public void testEncodingAndDecodingOfComplexType() throws PropertyValidationException {
        RoleData anybody = new RoleData(new Role(null, "anybody"));
        DynamicUiProperty<RoleData> roleProperty = new DynamicUiProperty<>("test",
                anybody, new HashSet<>(Arrays.asList(anybody)));
        roleProperty.setHasMultipleValues(true);
        List<String> encodedValues = roleProperty.getEncodedValues();  
        DynamicUiProperty<RoleData> rolePropertyCopy = new DynamicUiProperty<>("test",
                anybody, new HashSet<RoleData>());
        rolePropertyCopy.setHasMultipleValues(true);
        rolePropertyCopy.setEncodedValues(encodedValues);
        assertTrue("RoleData object didn't survive encodement/decodement", rolePropertyCopy.getValues().contains(anybody));
    }

    @Test
    public void testConstructors() {
        final RoleData anybody = new RoleData(new Role(null, "anybody"));
        DynamicUiProperty<RoleData> property = new DynamicUiProperty<>("someproperty", anybody);
        checkPropertyState(property, "constructor with default value");

        property = new DynamicUiProperty<>(property);
        checkPropertyState(property, "copy constructor");
    }

    @Test
    public void testSetValue() throws PropertyValidationException {
        final RoleData anybody = new RoleData(new Role(null, "anybody"));
        DynamicUiProperty<RoleData> property = new DynamicUiProperty<>();
        property.setValue(anybody);
        checkPropertyState(property, "setValue(something)");
        assertEquals(anybody, property.getValue());
        property.setValue(null);
        checkPropertyState(property, "setValue(null)");
        property.setEncodedValue(new DynamicUiProperty<RoleData>().getAsEncodedValue(anybody));
        checkPropertyState(property, "setEncodedValue(something)");
        assertEquals(anybody, property.getValue());
    }

    private void checkPropertyState(final DynamicUiProperty<RoleData> property, final String step) {
        property.getValue(); // Make sure we can get the value
        try {
            property.getValues();
            fail("getValues() call should not be allowed (at step \"" + step + "\").");
        } catch (IllegalStateException e) {
            // NOPMD expected
        }
    }

}
