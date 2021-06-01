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
package org.ejbca.ui.web;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;

import javax.faces.convert.ConverterException;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * A unit test for JSF converter.
 *
 * @version $Id$
 */
public class OIDStringLinkedHashSetConverterUnitTest {

    @SuppressWarnings("unchecked")
    @Test
    public void testStringToSet() {
        LinkedHashSet<String> set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("");
        assertTrue("Set from nothing should be empty", set.isEmpty());
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString(null);
        assertTrue("Set from null should be empty", set.isEmpty());
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1");
        assertEquals("Set should have the right size", 1, set.size());
        assertEquals("Set should have the right content", "1.1.1.1", set.toArray()[0]);
        try {
            set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1");
            fail("'1' is not a valid OID and should give validation error");
        } catch (ConverterException e) {
            assertEquals("Should give a good validation error message", "The value '1' is not a valid OID.", e.getMessage());
        }
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1,2.2.2.2");
        assertEquals("Set should have the right size", 2, set.size());
        assertEquals("Set should have the right content", "1.1.1.1", set.toArray()[0]);
        assertEquals("Set should have the right content", "2.2.2.2", set.toArray()[1]);
        try {
            set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1,2.2.2.2,3.3.3.3");
            fail("'3.3.3.3' is not a valid OID and should give validation error");
        } catch (ConverterException e) {
            assertEquals("Should give a good validation error message", "The value '3.3.3.3' is not a valid OID.", e.getMessage());
        }
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1,2.2.2.2,1.3.3.3.3");
        assertEquals("Set should have the right size", 3, set.size());
        assertEquals("Set should have the right content", "1.1.1.1", set.toArray()[0]);
        assertEquals("Set should have the right content", "2.2.2.2", set.toArray()[1]);
        assertEquals("Set should have the right content", "1.3.3.3.3", set.toArray()[2]);
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1, 2.2.2.2 , 1.3.3.3.3 ");
        assertEquals("Set should have the right size", 3, set.size());
        assertEquals("Set should have the right content", "1.1.1.1", set.toArray()[0]);
        assertEquals("Set should have the right content", "2.2.2.2", set.toArray()[1]);
        assertEquals("Set should have the right content", "1.3.3.3.3", set.toArray()[2]);
        set = (LinkedHashSet<String>) OIDStringLinkedHashSetConverter.getSetFromString("1.1.1.1, , 1.3.3.3.3 ");
        assertEquals("Set should have the right size", 2, set.size());
        assertEquals("Set should have the right content", "1.1.1.1", set.toArray()[0]);
        assertEquals("Set should have the right content", "1.3.3.3.3", set.toArray()[1]);
    }

    @Test
    public void testSetToString() {
        try {
            final String str = OIDStringLinkedHashSetConverter.getStringFromSet(new HashSet<String>());
            fail("Should throw IllegalArgumentException: " + str);
        } catch (IllegalArgumentException e) {
            assertEquals("Wrong error message", "Cannot convert class java.util.HashSet object to LinkedHashSet in OIDStringLinkedHashSetConverter.", e.getMessage());
        }
        String str = OIDStringLinkedHashSetConverter.getStringFromSet(new LinkedHashSet<Integer>(Arrays.asList(1)));
        assertEquals("Integer HashSet should give the string format", "1", str);
        str = OIDStringLinkedHashSetConverter.getStringFromSet(null);
        assertNull("Null input should give null output", str);
        str = OIDStringLinkedHashSetConverter.getStringFromSet(new LinkedHashSet<Integer>());
        assertEquals("Empty LinkedHashSet should give empty string", "", str);
        str = OIDStringLinkedHashSetConverter.getStringFromSet(new LinkedHashSet<String>(Arrays.asList("1.1.1.1")));
        assertEquals("Should be 1 item", "1.1.1.1", str);
        str = OIDStringLinkedHashSetConverter.getStringFromSet(new LinkedHashSet<String>(Arrays.asList("1.1.1.1", "2.2.2.2")));
        assertEquals("Should be 2 items", "1.1.1.1,2.2.2.2", str);
        str = OIDStringLinkedHashSetConverter.getStringFromSet(new LinkedHashSet<String>(Arrays.asList("1.1.1.1", "2.2.2.2", "3.3.3.3")));
        assertEquals("Should be 3 items", "1.1.1.1,2.2.2.2,3.3.3.3", str);
        
    }

}
