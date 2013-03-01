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
package org.cesecore.certificates.ca.catoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.junit.Test;

/**
 * Tests for parsing PKCS#11 properties, that can run without a HSM. 
 * 
 * @version $Id$
 */
public class CATokenParseTest {
    
    @Test
    public void testParseProperties() throws Exception {
        assertTrue(CAToken.getPropertiesFromString(null).isEmpty());
        assertTrue(CAToken.getPropertiesFromString("").isEmpty());
        assertTrue(CAToken.getPropertiesFromString("  ").isEmpty());
        assertTrue(CAToken.getPropertiesFromString("\n\n").isEmpty());
        assertTrue(CAToken.getPropertiesFromString("# comment").isEmpty());
        assertTrue(CAToken.getPropertiesFromString("\n# comment\n\n").isEmpty());
        
        Properties props = CAToken.getPropertiesFromString("a b");
        assertEquals(props.size(), 1);
        assertEquals(props.getProperty("a"), "b");
        
        props = CAToken.getPropertiesFromString("\na b\n");
        assertEquals(props.size(), 1);
        assertEquals(props.getProperty("a"), "b");
        
        props = CAToken.getPropertiesFromString("\na   b  \n");
        assertEquals(props.size(), 1);
        assertEquals(props.getProperty("a"), "b");
        
        props = CAToken.getPropertiesFromString("a 1\nb\t2 \nc  3  ");
        assertEquals(props.size(), 3);
        assertEquals(props.getProperty("a"), "1");
        assertEquals(props.getProperty("b"), "2");
        assertEquals(props.getProperty("c"), "3");
        
        props = CAToken.getPropertiesFromString("p C:\\test\\path");
        assertEquals(props.size(), 1);
        assertEquals(props.getProperty("p"), "C:\\test\\path");
    }
}
