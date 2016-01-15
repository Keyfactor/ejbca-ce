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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * 
 * @version $Id$
 */
public class SecureXMLDecoderTest {

    private static final Logger log = Logger.getLogger(SecureXMLDecoderTest.class);
    
    @Test
    public void testElementaryTypes() throws IOException {
        log.trace(">testElementaryTypes");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\"></java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<null/>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<char>A</char>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<char>&amp;</char>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<int>-12345</int>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<float>-12.34</float>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<string>hello</string>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<boolean>true</boolean>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n</object>\n</java>");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n" +
                    "<void method=\"add\">\n<int>123</int>\n</void>\n" +
                    "<void method=\"add\">\n<int>456</int>\n</void>\n" +
                    "</object>\n</java>");
        log.trace("<testElementaryTypes");
    }
    
    /**
     * Test deserialization of Lists and Maps.
     */
    @Test
    public void testBasicCollections() throws IOException {
        log.trace(">testBasicCollections");
        // Empty list
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n</object>\n</java>");
        // List of two integers
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n" +
                    "<void method=\"add\">\n<int>123</int>\n</void>\n" +
                    "<void method=\"add\">\n<int>456</int>\n</void>\n" +
                    "</object>\n</java>");
        // Map from int to string
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.LinkedHashMap\">\n" +
                "<void method=\"put\">\n<int>-1</int>\n<string>A</string>\n</void>\n" +
                "<void method=\"put\">\n<int>10</int>\n<string>B</string>\n</void>\n" +
                "</object>\n</java>");
        log.trace("<testBasicCollections");
    }
    
    @Test
    public void testMultipleObjects() throws IOException {
        log.trace(">testMultipleObjects");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<int>-12345</int>\n<string>ABC</string>\n</java>");
        log.trace(">testMultipleObjects");
    }
    
    /**
     * Encodes a complex value with the standard XMLEncoder and tries to decode it again.
     * @throws UnsupportedEncodingException 
     */
    @Test
    public void testComplexEncodeDecode() throws IOException {
        log.trace(">testComplexEncodeDecode");
        
        final Map<Object,Object> root = new LinkedHashMap<>();
        root.put("testfloat", 12.3);
        root.put("testnull", null);
        root.put("testutf8string", "Test ÅÄÖ \u4f60\u597d");
        root.put("testchar1", '<');
        root.put("testchar2", '\\');
        root.put("testchar3", 'å');
        root.put("testbool", false);
        root.put("testbyte", Byte.valueOf((byte)123));
        root.put("testshort", Short.valueOf((short)12345));
        final Set<Object> set = new HashSet<>();
        set.add("Test");
        set.add(12345);
        set.add(new ArrayList<String>());
        root.put("testhashset", set);
        root.put("testbytearray", new byte[] { -128, 0, 123, 45, 67, 89, 127 });
        root.put("teststringarray", new String[] { "Hello", "World" });
        final Map<Object,Object> map = new LinkedHashMap<>();
        map.put(123, "ABC");
        root.put("testmaparray", new Map[] { map });
        root.put("testbooleanarray", new boolean[] { true, false, true });
        root.put("testnestedarray", new byte[][] { new byte[] { 1, 2 }, new byte[] { 3, 4 } });
        
        final List<Object> list = new ArrayList<>(2);
        final Map<String,Long> nested = new HashMap<>();
        nested.put("testlong", Long.valueOf(Long.MAX_VALUE));
        list.add(nested);
        
        root.put("testlist", list);
        
        // Base64PutHashMap
        
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(root);
        encoder.close();
        
        // Try to decode it and compare
        decodeCompare(baos.toByteArray());
        
        log.trace("<testComplexEncodeDecode");
    }
    
    @Test
    public void testNotAllowedType() throws IOException {
        log.trace(">testNotAllowedType");
        
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(new Random()); // java.util.Random is serializable, but isn't whitelisted
        encoder.close();
        
        decodeBad(baos.toByteArray());
        
        log.trace("<testNotAllowedType");
    }
    
    @Test
    public void testNotAllowedMethod() throws IOException {
        log.trace(">testNotAllowedMethod");
        
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n" +
                "<void method=\"add\">\n<int>123</int>\n</void>\n" +
                "<void method=\"remove\">\n<int>0</int>\n</void>\n" +
                "</object>\n</java>";
        decodeBad(xml.getBytes());
        
        log.trace("<testNotAllowedMethod");
    }
    
    private void decodeBad(final byte[] xml) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">decodeBad(" + new String(xml) + ")");
        }
        
        try (XMLDecoder xmldec = new XMLDecoder(new ByteArrayInputStream(xml))) {
            xmldec.readObject();
            // Should succeed (XMLDecoder is insecure)
        }
        
        try (SecureXMLDecoder securedec = new SecureXMLDecoder(new ByteArrayInputStream(xml))) {
            securedec.readObject();
            fail("Should not accept arbitrary classes/methods");
        } catch (IOException e) {
            // NOPMD: Expected
        }
        
        log.trace("<decodeBad");
    }
    
    /**
     * Decodes an XML string with both the standard XMLDecoder and with SecureXMLDecoder, and compares the resulting objects.
     */
    private void decodeCompare(final String xml) throws IOException {
        decodeCompare(xml.getBytes());
    }
    
    private void decodeCompare(final byte[] xml) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">decodeCompare(" + new String(xml) + ")");
        }
        
        final List<Object> expectedObjs = new ArrayList<>();
        final List<Object> actualObjs = new ArrayList<>();
        
        try (XMLDecoder xmldec = new XMLDecoder(new ByteArrayInputStream(xml))) {
            int i = 1;
            while (true) {
                log.debug("Reading object " + (i++) + " from the standard JDK XMLDecoder");
                expectedObjs.add(xmldec.readObject());
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // NOPMD: Expected, happens when we reach the end
        }
        
        try (SecureXMLDecoder securedec = new SecureXMLDecoder(new ByteArrayInputStream(xml))) {
            int i = 1;
            while (true) {
                log.debug("Reading object " + (i++) + " from SecureXMLDecoder");
                actualObjs.add(securedec.readObject());
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // NOPMD: Expected, happens when we reach the end
        }
        
        // Compare the results
        assertEquals("Number of objects decoded from XML differ.", expectedObjs.size(), actualObjs.size());
        
        final int count = expectedObjs.size();
        log.debug("Comparing " + count + " objects");
        for (int i = 0; i < count; i++) {
            final Object expected = expectedObjs.get(i);
            final Object actual = actualObjs.get(i);
            compareObjects(expected, actual);
        }
        
        log.trace("<decodeCompare");
    }

    private void compareObjects(final Object expected, final Object actual) {
        if (log.isTraceEnabled()) {
            log.trace(">compareObjects(" + expected + ", " + actual + ")");
        }
        
        if (expected == null) {
            assertNull("Deserialized value should have been null", actual);
            return;
        }
        
        assertNotNull("Deserialized value should NOT be null", actual);
        
        assertEquals("Class of deserialized value differs.", expected.getClass(), actual.getClass());
        
        if (expected instanceof List) {
            final List<?> expectedList = (List<?>)expected;
            final List<?> actualList = (List<?>)actual;
            assertEquals("Number of elements in lists differ.", expectedList.size(), actualList.size());
            
            final Iterator<?> expectedIter = expectedList.iterator();
            final Iterator<?> actualIter = actualList.iterator();
            while (expectedIter.hasNext()) {
                final Object expectedElem = expectedIter.next();
                final Object actualElem = actualIter.next();
                compareObjects(expectedElem, actualElem);
            }
        } else if (expected instanceof LinkedHashMap) {
            final Map<?,?> expectedMap = (Map<?,?>)expected;
            final Map<?,?> actualMap = (Map<?,?>)actual;
            assertEquals("Number of elements in maps differ.", expectedMap.size(), actualMap.size());
            
            // For LinkedHashMaps we expect the entries to come in the same order
            final Iterator<?> expectedIter = expectedMap.entrySet().iterator();
            final Iterator<?> actualIter = expectedMap.entrySet().iterator();
            while (expectedIter.hasNext()) {
                final Map.Entry<?,?> expectedEntry = (Map.Entry<?,?>)expectedIter.next();
                final Map.Entry<?,?> actualEntry = (Map.Entry<?,?>)actualIter.next();
                compareObjects(expectedEntry.getKey(), actualEntry.getKey());
                compareObjects(expectedEntry.getValue(), actualEntry.getValue());
            }
        } else if (expected instanceof Map) {
            final Map<?,?> expectedMap = (Map<?,?>)expected;
            final Map<?,?> actualMap = (Map<?,?>)actual;
            assertEquals("Number of elements in maps differ.", expectedMap.size(), actualMap.size());
            
            for (Object key : expectedMap.keySet()) {
                final Object expectedValue = expectedMap.get(key);
                final Object actualValue = actualMap.get(key);
                compareObjects(expectedValue, actualValue);
            }
        } else if (expected.getClass().isArray()) {
            // Note: The array could be of a primitive type so we can't cast it to Object[]
            final int expectedLength = Array.getLength(expected);
            assertEquals("Number of array elements differ.", expectedLength, Array.getLength(actual));
            
            for (int i = 0; i < expectedLength; i++) {
                final Object expectedElem = Array.get(expected, i);
                final Object actualElem = Array.get(actual, i);
                compareObjects(expectedElem, actualElem);
            }
        } else {
            assertEquals("Deserialized values differ.", expected, actual);
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<compareObjects(" + expected + ", " + actual + ")");
        }
    }
    
    
    
}
