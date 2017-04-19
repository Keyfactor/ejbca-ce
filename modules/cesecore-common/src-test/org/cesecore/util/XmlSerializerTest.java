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

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Assert;
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
		Assert.assertEquals(VALUE, encDecAsXml(VALUE, true));
		log.trace("<serializeSimpleObject");
	}
	
	@Test
	public void serializeSpecialChars() {
		log.trace(">serializeSpecialChars");
		final String VALUE = "ĞİŞğışÅÄÖåäö";
		Assert.assertEquals(VALUE, encDecAsXml(VALUE, true));
		log.trace("<serializeSpecialChars");
	}
	
	@Test
    public void serializeSpecialCharsWithoutBase64() {
        log.trace(">serializeSpecialChars");
        final String VALUE = "ĞİŞğışÅÄÖåäö";
        final String encodedDecoded = (String)encDecAsXml(VALUE, false);
        Assert.assertEquals(VALUE, encodedDecoded);
        Assert.assertTrue("Special characters should not be entity encoded, or otherwise modified.", encodedDecoded.contains(VALUE));
        log.trace("<serializeSpecialChars");
    }
	
	@Test
	public void serializeSpecialXmlChars() {
		log.trace(">serializeSpecialXmlChars");
		final String VALUE = "</string>";
		Assert.assertEquals(VALUE, encDecAsXml(VALUE, true));
		log.trace("<serializeSpecialXmlChars");
	}
	
	/** Make a round trip using a xml enc and dec. */
	private Object encDecAsXml(String value, boolean useBase64) {
		final String KEY = "SomeKey";
		final Map<String,Object> inputMap = new LinkedHashMap<>();
		inputMap.put(KEY, value);
		final String encoded = useBase64 ? XmlSerializer.encode(inputMap) : XmlSerializer.encodeWithoutBase64(inputMap);
		log.debug(encoded);
		return XmlSerializer.decode(encoded).get(KEY);
	}
}
