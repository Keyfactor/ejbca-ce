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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.junit.Test;

/**
 * Tests key strings used for crypto tokens
 * 
 * @version $Id: PurposeMappingTest.java 389 2011-03-01 14:56:15Z tomas $
 */
public class PurposeMappingTest {

	
	@Test
	public void test01KeyStringsEmpty() throws Exception {
		PurposeMapping ks = new PurposeMapping(null);
		String[] strings = ks.getAliases();
		assertEquals(0, strings.length);
		// All keys should be "defaultKey" when we have not defined anything
		String key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		
		String alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertNull(alias);
		
		// Unknown will always return defaultKey
		key = ks.getPurposeProperty(4711);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		// Unknown will always return null
		alias = ks.getAlias(4711);
		assertNull(alias);		
	}

	public void test02KeyStringsSomeEmpty() throws Exception {
		Properties prop = new Properties();
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "mycertSignKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, "mytestKey");
		PurposeMapping ks = new PurposeMapping(prop);
		String[] strings = ks.getAliases();
		assertEquals(2, strings.length);
		// it's backed by a hashset so we really don't know the order, but this is what it is in jdk 6...
		assertEquals("mytestKey", strings[0]);
		assertEquals("mycertSignKey", strings[1]);
		// All keys should be "defaultKey" when we have not defined anything
		String key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, key);
		
		String alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals("mycertSignKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertNull(alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals("mytestKey", alias);
		
		// Unknown will always return defaultKey
		key = ks.getPurposeProperty(4711);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		// Unknown will always return null
		alias = ks.getAlias(4711);
		assertNull(alias);
	}

	public void test02KeyStringsAll() throws Exception {
		Properties prop = new Properties();
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "mycertSignKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, "mycertSignNextKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, "mycertSignPreviousKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "mycrlSignKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, "myhardTokenEncKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, "mykeyEncKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, "mytestKey");
		PurposeMapping ks = new PurposeMapping(prop);
		String[] strings = ks.getAliases();
		assertEquals(7, strings.length);
		// it's backed by a hashset so we really don't know the order, so make it into a collection instead
		List<String> list = Arrays.asList(strings);
		assertTrue(list.contains("mycertSignPreviousKey"));
		assertTrue(list.contains("mytestKey"));
		assertTrue(list.contains("mycertSignKey"));
		assertTrue(list.contains("mykeyEncKey"));
		assertTrue(list.contains("myhardTokenEncKey"));
		assertTrue(list.contains("mycertSignNextKey"));
		assertTrue(list.contains("mycrlSignKey"));
		assertTrue(list.contains("mytestKey"));
		// All keys should be "defaultKey" when we have not defined anything
		String key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, key);
		
		String alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals("mycertSignKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals("mycrlSignKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals("mycertSignNextKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals("mycertSignPreviousKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals("myhardTokenEncKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals("mykeyEncKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals("mytestKey", alias);
		
		// Unknown will always return defaultKey
		key = ks.getPurposeProperty(4711);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		// Unknown will always return null
		alias = ks.getAlias(4711);
		assertNull(alias);
	}

}
