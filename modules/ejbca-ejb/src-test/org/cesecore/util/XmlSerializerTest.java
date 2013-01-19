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
		Assert.assertEquals(VALUE, encDecAsXml(VALUE));
		log.trace("<serializeSimpleObject");
	}
	
	@Test
	public void serializeSpecialChars() {
		log.trace(">serializeSpecialChars");
		final String VALUE = "ĞİŞğışÅÄÖåäö";
		Assert.assertEquals(VALUE, encDecAsXml(VALUE));
		log.trace("<serializeSpecialChars");
	}
	
	@Test
	public void serializeSpecialXmlChars() {
		log.trace(">serializeSpecialXmlChars");
		final String VALUE = "</string>";
		Assert.assertEquals(VALUE, encDecAsXml(VALUE));
		log.trace("<serializeSpecialXmlChars");
	}
	
	/** Make a round trip using a xml enc and dec. */
	private Object encDecAsXml(String value) {
		final String KEY = "SomeKey";
		final Map<String,Object> inputMap = new LinkedHashMap<String,Object>();
		inputMap.put(KEY, value);
		final String encoded = XmlSerializer.encode(inputMap);
		log.debug(encoded);
		return XmlSerializer.decode(encoded).get(KEY);
	}
}
