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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleData;
import org.junit.Test;

/**
 * Unit Test for DynamicUiProperty.
 * 
 * DynamicUiProperty is serialized into DB (see ECA-9560 Fix DynamicUiProperty serialization 
 * into ProfileData table with approval profiles).
 * 
 * Therefore a serialization / deserialization test is required if the class has been changed 
 * (i.e. getters or setters renamed or removed, or more). See deserializeRelease7_5_0_DynamicUiProperty
 */
public class DynamicUiPropertyTest {

    private static final Logger log = Logger.getLogger(DynamicUiPropertyTest.class);
    
    final static private String roleName = "anybody";
    
    @Test
    public void testEncodingAndDecodingOfComplexType() throws PropertyValidationException {
        RoleData anybody = new RoleData(new Role(null, roleName));
        DynamicUiProperty<RoleData> roleProperty = new DynamicUiProperty<>("test",
                anybody, new HashSet<>(Collections.singletonList(anybody)));
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
        final RoleData anybody = new RoleData(new Role(null, roleName));
        DynamicUiProperty<RoleData> property = new DynamicUiProperty<>("someproperty", anybody);
        checkPropertyState(property, "constructor with default value");

        property = new DynamicUiProperty<>(property);
        checkPropertyState(property, "copy constructor");
    }

    @Test
    public void testSetValue() throws PropertyValidationException {
        final RoleData anybody = new RoleData(new Role(null, roleName));
        DynamicUiProperty<RoleData> property = new DynamicUiProperty<>();
        property.setType(RoleData.class);
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

    /**
     * Tests a property with multiple values. Both none, one and two values should be allowed.
     */
    @Test
    public void testGetMultiValue() throws PropertyValidationException {
        final List<String> possibleValues = new ArrayList<>(Arrays.asList("ABC", "123"));
        DynamicUiProperty<String> property = new DynamicUiProperty<>(String.class, "testproperty", null, possibleValues);
        property.setHasMultipleValues(true);
        assertNotNull("Should return an empty list, not null.", property.getValues());
        assertEquals("Should return an empty list.", 0, property.getValues().size());
        property.setValues(Arrays.asList("ABC"));
        assertEquals("Should return {\"ABC\"}.", new ArrayList<>(Collections.singletonList("ABC")), property.getValues());
        property.setValues(Arrays.asList("ABC", "123"));
        assertEquals("Should return {\"ABC\", \"123\"}.", new ArrayList<>(Arrays.asList("ABC", "123")), property.getValues());
        property.setValues(new ArrayList<>());
        assertNotNull("Should return an empty list, not null.", property.getValues());
        assertEquals("Should return an empty list.", 0, property.getValues().size());
    }
    
    @Test
    public void deserializeRelease7_5_0_DynamicUiProperty() throws Exception {
        final DynamicUiProperty<String> property = deserialize("/SerializedDynamicUiProperty750.dat");
        assertNotNull("Deserialized UI property must not be null.", property);
        assertEquals("Deserialized UI property name does not match.", "myName", property.getName());
        assertEquals("Deserialized UI property default value does not match.", "TestDynamicUiPropertyDeserialization750", property.getDefaultValue());
    }
    
    public static void serialize(final String filename, final Serializable serializable){
        try (FileOutputStream file = new FileOutputStream (filename); 
             ObjectOutputStream out = new ObjectOutputStream (file)) {      
            out.writeObject(serializable);       
        } catch (IOException e) {
            log.error(e);
            fail("Could not serialize and store DynamicUiProperty: " + e.getMessage());
        } 
    }
    
    @SuppressWarnings("unchecked")
    public static DynamicUiProperty<String> deserialize(final String filename) {
        final URL url = DynamicUiPropertyTest.class.getResource(filename);
        assertNotNull("Found serialized DynamicUiProperty path must not be null.", url);

        DynamicUiProperty<String> property = null;
        try (FileInputStream fis = new FileInputStream (url.getFile()); 
             ObjectInputStream in = new ObjectInputStream(fis)) {                                  
            property = (DynamicUiProperty<String>) in.readObject();  
        } 
        catch (IOException e) {
            log.error(e);
            fail("DynamicUiProperty serialized object file not found: " + e.getMessage());
        } 
        catch (ClassNotFoundException e) {
            log.error(e);
            fail("DynamicUiProperty serialized object class not found: " + e.getMessage());    
        }
        return property;
    }
    
//    public static void main(String[] args) {      
//        DynamicUiProperty<String> property = new DynamicUiProperty<>(String.class, "myName", "TestDynamicUiPropertyDeserialization750");
//        property.setValidator(StringValidator.base64Instance(1, 64));
//        serialize("<changePath>/SerializedDynamicUiProperty750.dat", property);
//        property = deserialize("<changePath>/SerializedDynamicUiProperty750.dat");
//    }
    
}
