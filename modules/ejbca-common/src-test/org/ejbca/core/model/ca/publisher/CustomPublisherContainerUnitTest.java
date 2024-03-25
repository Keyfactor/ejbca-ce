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
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertEquals;

import java.util.Set;
import java.util.TreeSet;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CustomPublisherContainerUnitTest {
    
    private static final Set<String> EMPTY_SET = new TreeSet<>(); 
    
    private static final Set<String> SIMPLE_SET = new TreeSet<>();
    
    private static final Set<String> PLACEHOLDER_SET = new TreeSet<>();
    
    static {
        SIMPLE_SET.add("prop");
        SIMPLE_SET.add("prop.dot.notation");
        
        PLACEHOLDER_SET.add("prop");
        PLACEHOLDER_SET.add("prop.dot.notation");
        PLACEHOLDER_SET.add("prop.sub.*");
        PLACEHOLDER_SET.add("prop.*.placeholder");
        PLACEHOLDER_SET.add("prop.sub.*.placeholder");
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
    
    @Test
    public void testFilterEmptyDeclaration() {
        // All empty.
        assertEquals("An empty set of properties cannot contain unsupported properties.", 
                EMPTY_SET, CustomPublisherContainer.filterUnsupportedProperties(EMPTY_SET, EMPTY_SET));
        
        // No properties declared, properties not empty.
        final Set<String> properties = new TreeSet<>();
        properties.add("unsupportedproperty");
        assertEquals("A non-empty set of undeclared properties must be unsupported.", 
                properties, CustomPublisherContainer.filterUnsupportedProperties(EMPTY_SET, properties));
    }
    
    @Test
    public void testFilterFixPropertiesSet() {
        
        // All properties declared.
        assertEquals("A set of declared properties must not return unsupported properties.", 
                EMPTY_SET, CustomPublisherContainer.filterUnsupportedProperties(SIMPLE_SET, SIMPLE_SET));
        
        // Test return value for an undeclared property.
        final Set<String> properties = new TreeSet<>(SIMPLE_SET);
        properties.add("unsupportedproperty");
        
        final Set<String> result = new TreeSet<>();
        result.add("unsupportedproperty");
        
        assertEquals("A set of partially declared properties must return the unsupported properties.", 
                result, CustomPublisherContainer.filterUnsupportedProperties(SIMPLE_SET, properties));
    }
    
    @Test
    public void testFilterPlaceholderPropertiesSet() {
        
        // All placeholder properties' placeholder are not from type long.
        final Set<String> result = new TreeSet<>(PLACEHOLDER_SET);
        result.removeAll(SIMPLE_SET);
        
        assertEquals("A set of declared placeholder properties with a non long data type must be unsupported.", 
                result, CustomPublisherContainer.filterUnsupportedProperties(PLACEHOLDER_SET, PLACEHOLDER_SET));
        
        // Filter declared placeholder properties.
        final Set<String> properties = new TreeSet<>();
        properties.add("prop.sub." + Long.MIN_VALUE);
        properties.add("prop.-123.placeholder");
        properties.add("prop.sub." + Long.MAX_VALUE + ".placeholder");
        
        assertEquals("A set of declared placeholder properties long data type must be supported.", 
                EMPTY_SET, CustomPublisherContainer.filterUnsupportedProperties(PLACEHOLDER_SET, properties));
    }
}
