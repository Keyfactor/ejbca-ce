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

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.junit.Test;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests of {@link SecureXMLDecoder}. This test covers deserialization of CESeCore classes only.
 * Tests of deserialization of EJBCA classes are in SecureXMLDecoderEjbcaUnitTest in ejbca-common.
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
                "</object>\n<object class=\"java.util.LinkedHashSet\">\n" +
                "<void method=\"add\">\n<int>-1</int>\n</void>\n" +
                "<void method=\"add\">\n<int>3</int>\n</void>\n" +
                "</object>\n</java>");
        log.trace("<testBasicCollections");
    }
    
    @Test
    public void testMultipleObjects() throws IOException {
        log.trace(">testMultipleObjects");
        decodeCompare("<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<int>-12345</int>\n<string>ABC</string>\n</java>");
        log.trace(">testMultipleObjects");
    }
    
    private static enum MockEnum {
        FOO;
    }
    
    /**
     * Tests encoding and decoding an enum 
     */
    @Test
    public void testEnum() throws IOException {        
        final Map<Object,Object> root = new LinkedHashMap<>();
        root.put("testEnum", MockEnum.FOO);
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(root);
        }
        // Try to decode it and compare
        decodeCompare(baos.toByteArray());
    }
    
    /**
     * Encodes a complex value with the standard XMLEncoder and tries to decode it again.
     */
    @Test
    public void testComplexEncodeDecode() throws IOException {
        log.trace(">testComplexEncodeDecode");
        
        final Map<Object,Object> root = new LinkedHashMap<>();
        root.put("testfloat", 12.3);
        root.put("testnull", null);
        root.put("testutf8string", "Test ÅÄÖ \u4f60\u597d");
        root.put("teststrangechars", "\0001\0002fooString");
        root.put("testchar1", '<');
        root.put("testchar2", '\\');
        root.put("testchar3", 'å');
        root.put("testbool", false);
        root.put("testemptyset", Collections.EMPTY_SET);
        root.put("testemptylist", Collections.emptyList());
        root.put("testClass", SecureXMLDecoder.class);
        final List<Object> unmodifiable = new ArrayList<>();
        unmodifiable.add('A');
        unmodifiable.add('B');
        root.put("testemptylist", Collections.unmodifiableList(unmodifiable));
        root.put("testbiginteger", new BigInteger("123456789123456789"));
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
        final Map<String, Integer> treeMap = new TreeMap<>(new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return o1.hashCode() - o2.hashCode();
            }
        });
        root.put("testdate", new Date(1457949109000L));
        root.put("testproperties0", new Properties());
        final Properties props1 = new Properties();
        props1.put("test.something", "value");
        root.put("testproperties1", props1);
        final Properties propsDefaults = new Properties();
        propsDefaults.put("test.something1", "default1");
        propsDefaults.put("test.something2", "default2");
        final Properties props2 = new Properties(propsDefaults);
        props2.put("test.something1", "override");
        root.put("testproperties2", props2);
        treeMap.put("aaa", 1);
        treeMap.put("bbb", 2);
        treeMap.put("ccc", 3);
        treeMap.put("ddd", 4);
        treeMap.put("eee", 5);
        root.put("testtreemap", treeMap);
        
        final List<Object> list = new ArrayList<>(2);
        final Map<String,Long> nested = new HashMap<>();
        nested.put("testlong", Long.valueOf(Long.MAX_VALUE));
        list.add(nested);
        root.put("testlist", list);
        
        final Map<Object,Object> propmap = new HashMap<>();
        root.put("b64getmap", new Base64GetHashMap(propmap));
        root.put("b64putmap", new Base64PutHashMap(propmap));
        
        root.put("certpolicy", new CertificatePolicy("1.2.3.4", "Finders keepers!", "http://example.com/policy"));
        
        // Base64PutHashMap
        
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(root);
        }
        
        // Try to decode it and compare
        decodeCompare(baos.toByteArray());
        
        log.trace("<testComplexEncodeDecode");
    }
    
    private static final class MockObject {
        private Integer integerValue;
        private int intValue;
        private boolean booleanValue;
        public Integer getIntegerValue() { return integerValue; }
        public void setIntegerValue(final Integer integerValue) { this.integerValue = integerValue; }
        public int getIntValue() { return intValue; }
        public void setIntValue(int intValue) { this.intValue = intValue; }
        public boolean getBooleanValue() { return booleanValue; }
        public void setBooleanValue(boolean booleanValue) { this.booleanValue = booleanValue; }
    }

    /** Tests properties with primitive types */
    @Test
    public void testPrimitiveTypeProperty() throws IOException {
        log.trace(">testPrimitiveTypeProperty");
        // Given
        final MockObject obj = new MockObject();
        obj.setIntegerValue(123);
        obj.setIntValue(456);
        obj.setBooleanValue(true);
        // When
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(obj);
        }
        decodeCompare(baos.toByteArray());
        log.trace("<testPrimitiveTypeProperty");
    }
    
    /** Tests property with null value */
    @Test
    public void testNullProperty() throws IOException {
        log.trace(">testNullProperty");
        // Given
        final CertificatePolicy certPolicy = new CertificatePolicy("2.999.123", null, null);
        // When
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(certPolicy);
        }
        decodeCompare(baos.toByteArray());
        log.trace("<testNullProperty");
    }

    /** Tests decoding of an empty object */
    @Test
    public void testEmptyObject() throws IOException {
        log.trace(">testEmptyObject");
        // Given
        final CertificatePolicy certPolicy = new CertificatePolicy(null, null, null);
        // When
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(certPolicy);
        }
        decodeCompare(baos.toByteArray());
        log.trace("<testEmptyObject");
    }

    /** Tests properties with referenced object */
    @Test
    public void testReferencedObject() throws IOException {
        log.trace(">testReferencedObject");
        // Given
        final PKIDisclosureStatement obj = new PKIDisclosureStatement("http://example.com", "sv");
        final Map<String,Object> map = new LinkedHashMap<>();
        map.put("A", obj);
        map.put("B", obj);
        // When
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(map);
        }
        if (log.isTraceEnabled()) {
            log.trace("Encoded:\n" + baos.toString("UTF-8"));
        }
        final Map<?,?> decodedMap;
        try (SecureXMLDecoder securedec = new SecureXMLDecoder(new ByteArrayInputStream(baos.toByteArray()))) {
            decodedMap = (Map<?,?>) securedec.readObject();
        }
        // Then
        assertNotNull("Decoded map was null.", decodedMap);
        assertEquals("Object was not equal after decoding.", obj, decodedMap.get("A"));
        assertSame("Reference was not same.", decodedMap.get("A"), decodedMap.get("B"));
        log.trace("<testReferencedObject");
    }

    @Test
    public void testNotAllowedType() {
        log.trace(">testNotAllowedType");
        
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(new Random()); // java.util.Random is serializable, but isn't whitelisted
        }
        
        decodeBad(baos.toByteArray());
        
        log.trace("<testNotAllowedType");
    }
    
    @Test
    public void testDecodeUnknownClass() {
        final Map<Object,Object> root = new LinkedHashMap<>();

        root.put("testClass", Object.class);
        
        // Encode
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(root);
        }
        
        // Try to decode it and compare
        try {
            decodeCompare(baos.toByteArray());
            fail("Test should have failed when decoding an unauthorized class.");
        } catch (IOException e) {
            
        }

    }
    
    @Test
    public void testNotAllowedMethod() {
        log.trace(">testNotAllowedMethod");
        
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n<object class=\"java.util.ArrayList\">\n" +
                "<void method=\"add\">\n<int>123</int>\n</void>\n" +
                "<void method=\"remove\">\n<int>0</int>\n</void>\n" +
                "</object>\n</java>";
        decodeBad(xml.getBytes());
        
        log.trace("<testNotAllowedMethod");
    }
    
    private Object deserializeObject(final String xml) throws IOException {
        Object result = null;
        try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.US_ASCII)))) {
            result = decoder.readObject();
            decoder.readObject(); // Should trigger EOF
            fail("Too many objects in stream?");
        } catch (EOFException e) {
            // NOPMD: Expected, happens when we reach the end
        }
        return result;
    }

    @Test
    public void oldJava6EnumEncoding() throws IOException {
        log.trace(">oldJava6EnumEncoding");
        // Given
        final String xml = "<java version=\"1.6.0_45\" class=\"java.beans.XMLDecoder\">\n" +
                " <object class=\"java.util.HashMap\">\n" +
                "  <void method=\"put\">\n" +
                "   <string>KEY1</string>\n" +
                "   <object class=\"org.cesecore.util.SecureXMLDecoderTest$MockEnum\" method=\"valueOf\">\n" +
                "    <string>FOO</string>\n" +
                "   </object>\n" +
                "  </void>\n" +
                " </object>\n" +
                "</java>\n";
        // When
        final Object result = deserializeObject(xml);
        // Then
        final Map<?,?> map = (Map<?,?>) result;
        assertNotNull("Result was null.", map);
        final Object value = map.get("KEY1");
        assertSame("Wrong value was deserialized", MockEnum.FOO, value);
        log.trace("<oldJava6EnumEncoding");
    }

    /**
     * EJBCA 7.4.0 - 7.4.2 encoded PKI Disclosure Statements in Certificate Profiles incorrectly (see ECA-9548).
     * We need to support decoding incorrectly encoded PKI Disclosure Statements from those versions,
     * and that is what this test checks.
     */
    @Test
    public void decodeCorruptPkiDSFromEjbca740() throws Exception {
        log.trace(">decodeCorruptPkiDSFromEjbca740");
        // Given
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<java version=\"11.0.9\" class=\"java.beans.XMLDecoder\">\n" +
                " <object class=\"org.cesecore.util.Base64PutHashMap\">\n" +
                "  <void method=\"put\">\n" +
                "   <string>msg</string>\n" +
                "   <string>Edited certificateprofile tset.</string>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>changed:useqcstatement</string>\n" +
                "   <string>true</string>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>addedvalue:qcetsipds</string>\n" +
                "   <object class=\"java.util.ArrayList\">\n" +
                "    <void method=\"add\">\n" +
                "     <object>{en}https://cdn.vm.test/etsi_pds_en_server.pdf</object>\n" +
                "    </void>\n" +
                "   </object>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>changed:approvals</string>\n" +
                "   <string>{REVOCATION=-1, KEYRECOVER=-1, ADDEDITENDENTITY=-1}</string>\n" +
                "  </void>\n" +
                " </object>\n" +
                "</java>\n";
        // When
        final Object result = deserializeObject(xml);
        // Then
        final Map<?,?> map = (Map<?,?>) result;
        assertNotNull("Result was null.", map);
        final List<?> pds = (List<?>) map.get("addedvalue:qcetsipds");
        assertEquals("Wrong size of PDS list", 1, pds.size());
        final PKIDisclosureStatement pkids = (PKIDisclosureStatement) pds.get(0);
        assertEquals("Wrong PKI DS language", "en", pkids.getLanguage());
        assertEquals("Wrong PKI DS URL", "https://cdn.vm.test/etsi_pds_en_server.pdf", pkids.getUrl());
        log.trace("<decodeCorruptPkiDSFromEjbca740");
    }

    @Test
    public void test() throws Exception {
        log.trace(">decodeExtendedInformationNormal");
        // Given
        final String xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "\n" +
                "<java version=\"1.8.0_292\" class=\"java.beans.XMLDecoder\">\n" +
                "\n" +
                "<object class=\"org.cesecore.util.Base64PutHashMap\">\n" +
                "  <void method=\"put\">\n" +
                "   <string>version</string>\n" +
                "   <float>4.0</float>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>type</string>\n" +
                "   <int>0</int>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>subjectdirattributes</string>\n" +
                "   <string></string>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>maxfailedloginattempts</string>\n" +
                "   <int>-1</int>\n" +
                "  </void>\n" +
                "  <void method=\"put\">\n" +
                "   <string>remainingloginattempts</string>\n" +
                "   <int>-1</int>\n" +
                "  </void>\n" +
                "</object>\n" +
                "</java>\n";
        // When
        final Object result = deserializeObject(xml);
        // Then
        assertNotNull(result);
        assertTrue(result instanceof Base64PutHashMap);
        final Base64PutHashMap map = (Base64PutHashMap) result;
        assertEquals(-1, map.get("remainingloginattempts"));
        log.trace("<decodeExtendedInformationNormal");
    }

    private void decodeBad(final byte[] xml) {
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
        } catch (EOFException e) {
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
        } else if (expected instanceof LinkedHashMap || expected instanceof TreeMap) {
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
        } else if (expected instanceof CertificatePolicy) {
            final CertificatePolicy expectedCertPolicy = (CertificatePolicy) expected;
            final CertificatePolicy actualCertPolicy = (CertificatePolicy) actual;
            assertEquals("Deserialized CertificatePolicy object differ", expectedCertPolicy, actualCertPolicy);
        } else if (expected instanceof MockObject) {
            final MockObject expectedMock = (MockObject) expected;
            final MockObject actualMock = (MockObject) actual;
            assertEquals("Deserialized Integer properties differ", expectedMock.getIntegerValue(), actualMock.getIntegerValue());
            assertEquals("Deserialized int properties differ", expectedMock.getIntValue(), actualMock.getIntValue());
            assertEquals("Deserialized boolean properties differ", expectedMock.getBooleanValue(), actualMock.getBooleanValue());
        } else {
            assertEquals("Deserialized values differ.", expected, actual);
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<compareObjects(" + expected + ", " + actual + ")");
        }
    }
    
    
    
}
