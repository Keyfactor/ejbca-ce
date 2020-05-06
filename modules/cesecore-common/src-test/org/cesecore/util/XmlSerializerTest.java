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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityApprovalRequest;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test that XML serialization works as expected.
 * 
 * @version $Id$
 */
public class XmlSerializerTest {
	
	private static final Logger log = Logger.getLogger(XmlSerializerTest.class);

	@Test
	public void serializeSimpleObject() {
		log.trace(">serializeSimpleObject");
		final String VALUE = "testValue";
		assertEquals(VALUE, encDecAsXml(VALUE, true, false));
		log.trace("<serializeSimpleObject");
	}
	
	@Test
	public void serializeSpecialChars() {
		log.trace(">serializeSpecialChars");
		final String VALUE = "ĞİŞğışÅÄÖåäö";
		assertEquals(VALUE, encDecAsXml(VALUE, true, true));
		log.trace("<serializeSpecialChars");
	}
	
	@Test
    public void serializeSpecialCharsWithoutBase64() {
        log.trace(">serializeSpecialChars");
        final String VALUE = "ĞİŞğışÅÄÖåäö";
        final String encodedDecoded = (String)encDecAsXml(VALUE, false, false);
        assertEquals(VALUE, encodedDecoded);
        log.trace("<serializeSpecialChars");
    }
	
	@Test
	public void serializeSpecialXmlChars() {
		log.trace(">serializeSpecialXmlChars");
		final String VALUE = "</string>";
		assertEquals(VALUE, encDecAsXml(VALUE, true, false));
		log.trace("<serializeSpecialXmlChars");
	}
	
	/** Tests the simple and fast hand coding of XMLEncoded limited Map objects
	 * Compares to XMLEncoder to ensue it gives the same byte-for-byte output 
	 * @see XmlSerializer#encodeSimpleMapFast(Map)
	 */
	@Test
	public void encodeSimpleMapFast() throws IOException {
	    // Test null first
        assertNull("Encoding null should return null", XmlSerializer.encode(null));
	    assertNull("Encoding null should return null", XmlSerializer.encodeSimpleMapFast(null));
        assertNull("Encoding null should return null", XmlSerializer.encodeSimpleMapFastWithBase64(null));
	    // Test to encode ExtendedInformation, which is a standard class we always want to be able to encode fast
        ExtendedInformation extendedinformation = new ExtendedInformation();
        extendedinformation.setCertificateSerialNumber(new BigInteger("123"));
        extendedinformation.setExtensionData("foo", "baråäö");
        extendedinformation.setExtensionData("bar", "sdfasdfasdfahsdkjfHWELKRHQWEKLJFHWLKFUWGEFILU  3YR8O723RIUHLI23UGLKQWEFG   OWEUDIGQWkjlrg  qweudiQWHELFJKgfkjasgfsaljfgALJGEuyfgASLFGElfgewfui glfkJA");
        extendedinformation.setMaxLoginAttempts(4);
        extendedinformation.setSubjectDirectoryAttributes("myattr=I am from sweeeeden");
        // We need our own approvalClass since we don't have an impl in CESeCore
        class TestApprovalRequest implements EndEntityApprovalRequest {
            @Override
            public EndEntityInformation getEndEntityInformation() {
                return null;
            }           
        }
        extendedinformation.cacheApprovalType(TestApprovalRequest.class); 

        final HashMap<Object, Object> b64DataMap = new Base64PutHashMap();
        b64DataMap.putAll(extendedinformation.getRawData());
        b64DataMap.put("longvalue", Long.valueOf(123456789L));
        b64DataMap.put("boolvalue", Boolean.valueOf(true));
        b64DataMap.put("doublevalue", Double.valueOf("1.25"));
        b64DataMap.put("nullvalue", null);
        final Date dateValue = new Date();
        b64DataMap.put("datevalue", dateValue);
        // We use an embedded Properties<String,String> in some audit record log lines
        final Properties prop = new Properties();
        prop.put("property1", "value1");
        prop.put("tokensequence", "00000");
        b64DataMap.put("tokenproperties", prop);
        final LinkedHashMap<String, String> map = new LinkedHashMap<String, String>();
        map.put("akey", "avalue");
        map.put("bkey", "bvalue");
        map.put("nullkey", null);
        b64DataMap.put("linkedhashmap", map);
        final ArrayList<String> list = new ArrayList<String>();
        list.add("listitem1");
        list.add("listitem2");
        b64DataMap.put("araylist", list);
        final String xmlFast = XmlSerializer.encodeSimpleMapFast(b64DataMap);
        log.debug("XmlSerializer.encodeSimpleMapFast produced XML:\n" + xmlFast);
        // The actual length depends on version of java as the second line contains java version
        // <java version="1.8.0_252" class="java.beans.XMLDecoder">
        final String javaVersion = System.getProperty("java.version");
        final int length = 2642 + javaVersion.length(); 
        assertEquals("The Fast output XML should be " + length + " bytes", length, xmlFast.length());
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(os);) {
            encoder.writeObject(b64DataMap);
        }
        final String xmlJava = os.toString();
        log.debug("XMLEncoder produced XML:\n" + xmlJava);
        // Sanity checks
        assertEquals("The Java output XML should be " + length + " bytes", length, xmlJava.length());
        // Byte for byte, It should be exactly equals
        assertTrue("Fast encoded XML vs XMLEncoder was not byte-for-byte the same", ArrayUtils.isEquals(xmlFast.getBytes(StandardCharsets.UTF_8), xmlJava.getBytes(StandardCharsets.UTF_8)));

	    // Test decode with XMLDecoder
        final ExtendedInformation ei = EndEntityInformation.getExtendedInformationFromStringData(xmlFast);
        assertEquals("decoded serial number was not the one we encoded", new BigInteger("123"), ei.certificateSerialNumber());
        assertEquals("decoded extension data 'foo' was not the one we encoded", "baråäö", ei.getExtensionData("foo"));
        assertEquals("decoded extension data 'bar' was not the one we encoded", "sdfasdfasdfahsdkjfHWELKRHQWEKLJFHWLKFUWGEFILU  3YR8O723RIUHLI23UGLKQWEFG   OWEUDIGQWkjlrg  qweudiQWHELFJKgfkjasgfsaljfgALJGEuyfgASLFGElfgewfui glfkJA", ei.getExtensionData("bar"));
        assertEquals("decoded max login attempts was not the one we encoded", 4, ei.getMaxLoginAttempts());
        assertEquals("decoded subject directory attributes was not the one we encoded", "myattr=I am from sweeeeden", ei.getSubjectDirectoryAttributes());
        assertEquals("decoded approval type was not the one we encoded", TestApprovalRequest.class, ei.getCachedApprovalType());
        
	    // Test adding something that fails with IllegalArgumentException
        final HashMap<Object, Object> failingMap = new Base64PutHashMap();
        failingMap.put("longvalue", Long.valueOf(123456789L)); // this works
        XmlSerializer.encodeSimpleMapFast(failingMap);
        failingMap.put("list", new HashSet<String>()); // this should fail
        try {
            XmlSerializer.encodeSimpleMapFast(failingMap);
            fail("encodeSimpleMapFast should not handle HashSet");
        } catch (IllegalArgumentException e) {
            assertEquals("Error message is wrong", "encodeSimpleMapFast does not handle type: java.util.HashSet", e.getMessage());
        }
	}
	
	/** Make a round trip using a xml enc and dec. */
	private Object encDecAsXml(String value, boolean useBase64, boolean expectBase64) {
		final String KEY = "SomeKey";
		final Map<String,Object> inputMap = new LinkedHashMap<>();
		inputMap.put(KEY, value);
		final String encoded = useBase64 ? XmlSerializer.encode(inputMap) : XmlSerializer.encodeWithoutBase64(inputMap);
		log.debug(encoded);
		if (expectBase64) {
		    assertTrue("Special characters should be B64: encoded", encoded.contains("B64:"));
		} else {
		    assertTrue("Special characters should not be entity encoded, or otherwise modified.", encoded.contains(value));
		}
		return XmlSerializer.decode(encoded).get(KEY);
	}
}
