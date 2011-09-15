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
 * @version $Id$
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
		// NEXT and PREVIOUS does not return defaultKey
		assertNull("Should return null, since we don't have it defined", key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull("Should return null, since we don't have it defined", key);
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
	
	@Test
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
		assertNull("Should return null, since we don't have it defined", key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull("Should return null, since we don't have it defined", key);
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

	@Test
	public void test03KeyStringsAll() throws Exception {
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

	@Test
	public void test04PreviousAndNextSignKey() throws Exception {
		Properties prop = new Properties();
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "mycertSignKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "mycrlSignKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, "myhardTokenEncKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, "mykeyEncKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, "mytestKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, "mydefaultKey");
		PurposeMapping ks = new PurposeMapping(prop);
		String[] strings = ks.getAliases();
		assertEquals(6, strings.length);
		// it's backed by a hashset so we really don't know the order, so make it into a collection instead
		List<String> list = Arrays.asList(strings);
		assertTrue(list.contains("mytestKey"));
		assertTrue(list.contains("mycertSignKey"));
		assertTrue(list.contains("mykeyEncKey"));
		assertTrue(list.contains("myhardTokenEncKey"));
		assertTrue(list.contains("mycrlSignKey"));
		assertTrue(list.contains("mydefaultKey"));
		// All keys have defined values
		String key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertNull("Should return null, since we don't have it defined", key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull("Should return null, since we don't have it defined", key);
		
		String alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		assertEquals("mycertSignKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
		assertEquals("mycrlSignKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertNull("Should return null, since we don't have it defined", key);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertNull("Should return null, since we don't have it defined", key);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
		assertEquals("myhardTokenEncKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals("mykeyEncKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_KEYTEST);
		assertEquals("mytestKey", alias);
		
		// Unknown will always return defaultKey
		key = ks.getPurposeProperty(4711);
		assertEquals(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, key);
		// Unknown will not return null, becuase we have default defined
		alias = ks.getAlias(4711);
		assertEquals("mydefaultKey", alias);
		
		// Now define next and previous
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, "mycertSignNextKey");
		prop.put(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, "mycertSignPreviousKey");
		ks = new PurposeMapping(prop);
		strings = ks.getAliases();
		assertEquals(8, strings.length);
		// it's backed by a hashset so we really don't know the order, so make it into a collection instead
		list = Arrays.asList(strings);
		assertTrue(list.contains("mycertSignPreviousKey"));
		assertTrue(list.contains("mycertSignNextKey"));
		assertTrue(list.contains("mytestKey"));
		assertTrue(list.contains("mycertSignKey"));
		assertTrue(list.contains("mykeyEncKey"));
		assertTrue(list.contains("myhardTokenEncKey"));
		assertTrue(list.contains("mycrlSignKey"));
		assertTrue(list.contains("mydefaultKey"));
		
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, key);
		key = ks.getPurposeProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, key);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
		assertEquals("mycertSignNextKey", alias);
		alias = ks.getAlias(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		assertEquals("mycertSignPreviousKey", alias);

	}

}
