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

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.endentity.EndEntityApprovalRequest;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test that XML serialization works as expected.
 * 
 * @version $Id$
 */
public class XmlSerializerUnitTest {
	
	private static final Logger log = Logger.getLogger(XmlSerializerUnitTest.class);

	@Rule
    public ExpectedException expectedException = ExpectedException.none();

    // We need our own approvalClass since we don't have an impl in CESeCore
    private static class TestApprovalRequest implements EndEntityApprovalRequest {
        @Override
        public EndEntityInformation getEndEntityInformation() {
            return null;
        }
    }

    // Load expected XML
    private final TestFileResource testFileResource = new TestFileResource("XmlSerializerUnitTest_SimpleMapFast.xml");
    // Shared data set, compatible with data in XmlSerializerUnitTest_SimpleMapFast.xml
    private final BigInteger certificateSerialNumber = new BigInteger("123");
    private final String extensionData0Key = "foo";
    private final String extensionData0Value = "baråäö";
    private final String extensionData1Key = "bar";
    private final String extensionData1Value = "sdfasdfasdfahsdkjfHWELKRHQWEKLJFHWLKFUWGEFILU  3YR8O723RIUHLI23UGLKQWEFG   OWEUDIGQWkjlrg  qweudiQWHELFJKgfkjasgfsaljfgALJGEuyfgASLFGElfgewfui glfkJA";
    private final int maxLoginAttempts = 4;
    private final String subjectDirectoryAttributes = "myattr=I am from sweeeeden";
    private final int editEndEntityApprovalRequestId = 4712;

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

    @Test
    public void encodeNullSimpleMapFast() {
        // Test null first
        assertNull("Encoding null should return null", XmlSerializer.encode(null));
        assertNull("Encoding null should return null", XmlSerializer.encodeSimpleMapFast(null));
        assertNull("Encoding null should return null", XmlSerializer.encodeSimpleMapFastWithBase64(null));
    }

	/** Tests the simple and fast hand coding of XMLEncoded limited Map objects
	 * Compares to XMLEncoder to ensue it gives the same byte-for-byte output 
	 * @see XmlSerializer#encodeSimpleMapFast(Map)
	 */
	@Test
	public void encodeSimpleMapFast() throws IOException {
	    // Test data set compatible with XmlSerializerUnitTest_SimpleMapFast.xml
        // Set specific date to support the expected file
        final Date dateValue = Date.from(LocalDateTime
                .of(2020, 5, 21, 12, 13, 14)
                .toInstant(ZoneOffset.UTC)
        );
        // tokenproperties
        // We use an embedded Properties<String, String> in some audit record log lines
        final Properties tokenproperties = new Properties();
        final String tokensequence = "tokensequence";
        final String tokensequenceValue = "00000";
        tokenproperties.put(tokensequence, tokensequenceValue);
        // linkedhashmap
        final LinkedHashMap<String, String> linkedhashmap = new LinkedHashMap<>();
        linkedhashmap.put("akey", "avalue");
        linkedhashmap.put("bkey", "bvalue");
        linkedhashmap.put("nullkey", null);
        // arraylist
        final ArrayList<Object> arraylist = new ArrayList<>();
        arraylist.add("listitem1");
        arraylist.add(4711);
        // Read expected XML from file and replace it's java version with the actual one from current environment, add a line break to the end
        final String expectedXmlSerializerXmlString = testFileResource
                .getFileContent()
                .replaceAll("<java version=\"[^\"]+\"",
                        "<java version=\"" + System.getProperty("java.version") + "\""
                ) + "\n";

	    // Test to encode ExtendedInformation, which is a standard class we always want to be able to encode fast
        ExtendedInformation extendedinformation = new ExtendedInformation();
        extendedinformation.setCertificateSerialNumber(certificateSerialNumber);
        extendedinformation.setExtensionData(extensionData0Key, extensionData0Value);
        extendedinformation.setExtensionData(extensionData1Key, extensionData1Value);
        extendedinformation.setMaxLoginAttempts(maxLoginAttempts);
        extendedinformation.setSubjectDirectoryAttributes(subjectDirectoryAttributes);
        extendedinformation.cacheApprovalType(TestApprovalRequest.class);
        extendedinformation.addEditEndEntityApprovalRequestId(editEndEntityApprovalRequestId);
        // PKIDisclosureStatement
        PKIDisclosureStatement pds = new PKIDisclosureStatement();
        pds.setLanguage("SE");
        pds.setUrl("http://example.com/pdsåäö");
        //
        final HashMap<Object, Object> b64DataMap = new Base64PutHashMap();
        b64DataMap.putAll(extendedinformation.getRawData());
        b64DataMap.put("longvalue", 123456789L);
        b64DataMap.put("boolvalue", Boolean.TRUE);
        b64DataMap.put("doublevalue", 1.25d);
        b64DataMap.put("nullvalue", null);
        b64DataMap.put("datevalue", dateValue);
        b64DataMap.put("tokenproperties", tokenproperties);
        b64DataMap.put("linkedhashmap", linkedhashmap);
        b64DataMap.put("arraylist", arraylist);
        b64DataMap.put("pds", pds);

        // Get XML from XmlSerializer
        final String xmlSerializerXmlString = XmlSerializer.encodeSimpleMapFast(b64DataMap);
        // Get XML from XMLEncoder
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(os)) {
            encoder.writeObject(b64DataMap);
        }
        final String xmlEncoderXmlString = os.toString("UTF-8");

        log.debug("XmlSerializerUnitTest_SimpleMapFast.xml content XML:\n" + expectedXmlSerializerXmlString);
        log.debug("XmlSerializer.encodeSimpleMapFast produced XML:\n" + xmlSerializerXmlString);
        log.debug("XMLEncoder produced XML:\n" + xmlEncoderXmlString);

        assertEquals("The Fast output XML is not equal to the expected one", expectedXmlSerializerXmlString, xmlSerializerXmlString);

        // Byte for byte, It should be exactly equals
        assertTrue("Fast encoded XML vs XMLEncoder was not byte-for-byte the same", ArrayUtils.isEquals(xmlSerializerXmlString.getBytes(StandardCharsets.UTF_8), xmlEncoderXmlString.getBytes(StandardCharsets.UTF_8)));
        
	}

    // Test adding something that fails (internally) with IllegalArgumentException, we then fall back to XMLEncoder
	@Test
	public void encodeSimpleMapFastUnhandled() throws UnsupportedEncodingException {
        // Encode something we know encodeSimpleMapFast does not handle
        final HashMap<Object, Object> b64DataMapUnhandled = new Base64PutHashMap();
        b64DataMapUnhandled.put("stringbuffer", new StringBuffer());
        try {
            XmlSerializer.encodeSimpleMapFastInternal(b64DataMapUnhandled);
            fail("IllegalArgumentException should have been thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("Exception message was wrong", "encodeSimpleMapFast does not handle type: java.lang.StringBuffer", e.getMessage());
        }
        final String unhandled = XmlSerializer.encodeSimpleMapFast(b64DataMapUnhandled);
        // Get XML from XMLEncoder
        final ByteArrayOutputStream os1 = new ByteArrayOutputStream();
        try (final XMLEncoder encoder = new XMLEncoder(os1)) {
            encoder.writeObject(b64DataMapUnhandled);
        }
        final String handledByXMLEncoder = os1.toString("UTF-8");
        assertTrue("Fall back encodeSimpleMapFast vs XMLEncoder was not byte-for-byte the same", ArrayUtils.isEquals(handledByXMLEncoder.getBytes(StandardCharsets.UTF_8), unhandled.getBytes(StandardCharsets.UTF_8)));
	}
	
    // Test adding something that fails with IllegalArgumentException
    @Test
    public void encodeSimpleMapFastWithIllegalArgumentException() {
        // given
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("encodeSimpleMapFast does not handle type: java.io.File");
        final HashMap<Object, Object> failingMap = new Base64PutHashMap();
        failingMap.put("longvalue", 123456789L); // this works
        failingMap.put("unsupported", new File("bad")); // this should fail
        // when
        XmlSerializer.encodeSimpleMapFastInternal(failingMap);
    }


    // Test decode with XMLDecoder
	@Test
    public void decodeWithXMLDecoder() throws IOException {
	    // given
        final String xmlSerializerXmlString = testFileResource.getFileContent();
        // when
        final ExtendedInformation extendedInformation = EndEntityInformation.getExtendedInformationFromStringData(xmlSerializerXmlString);
        // then
        assertEquals("decoded serial number was not the one we encoded", certificateSerialNumber, extendedInformation.certificateSerialNumber());
        assertEquals("decoded extension data 'foo' was not the one we encoded", extensionData0Value, extendedInformation.getExtensionData(extensionData0Key));
        assertEquals("decoded extension data 'bar' was not the one we encoded", extensionData1Value, extendedInformation.getExtensionData(extensionData1Key));
        assertEquals("decoded max login attempts was not the one we encoded", maxLoginAttempts, extendedInformation.getMaxLoginAttempts());
        assertEquals("decoded subject directory attributes was not the one we encoded", subjectDirectoryAttributes, extendedInformation.getSubjectDirectoryAttributes());
        assertEquals("decoded approval type was not the one we encoded", TestApprovalRequest.class, extendedInformation.getCachedApprovalType());
        assertEquals("decoded approval request ID was not the one we encoded", Integer.valueOf(editEndEntityApprovalRequestId), extendedInformation.getEditEndEntityApprovalRequestIds().get(0));
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
