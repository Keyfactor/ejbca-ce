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
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Test;

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
