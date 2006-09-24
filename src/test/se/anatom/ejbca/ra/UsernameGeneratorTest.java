package se.anatom.ejbca.ra;

import junit.framework.TestCase;

import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;

public class UsernameGeneratorTest extends TestCase {

	/*
	 * Test method for 'org.ejbca.core.model.ra.UsernameGenerator.UsernameGenerator(String)'
	 */
	public void testUsernameGeneratorRandom() {
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGeneratorParams.RANDOM);
		String u = gen.generateUsername();
		assertEquals(u.length(), 12);
		
		UsernameGeneratorParams params = gen.getParams();
		params.setRandomNameLength(5);
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 5);
		
		params.setPrefix("foo-");
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 9);
		assertTrue(u.startsWith("foo-"));

		params.setPostfix("-foo");
		params.setPrefix(null);
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 9);
		assertTrue(u.endsWith("-foo"));
		
		params.setPrefix("foo-${RANDOM}");
		params.setPostfix(null);
		params.setRandomPrefixLength(6);
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 15);
		assertTrue(u.startsWith("foo-"));

		params.setPostfix("${RANDOM}-foo");
		params.setPrefix(null);
		params.setRandomPrefixLength(5);
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 14);
		assertTrue(u.endsWith("-foo"));
		
		params.setPrefix("foo-");
		gen.setParams(params);
		u = gen.generateUsername();
		assertEquals(u.length(), 18);
		assertTrue(u.endsWith("-foo"));
		assertTrue(u.startsWith("foo-"));
	}

	public void testUsernameGeneratorDN() {
		String dn = "C=SE, O=FooO, UID=foo, CN=bar";
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGeneratorParams.DN);
		String u = gen.generateUsername(dn);
		assertEquals(u, "bar");
		
		UsernameGeneratorParams params = gen.getParams();
		params.setDNGeneratorComponent("UID");
		gen.setParams(params);
		u = gen.generateUsername(dn);
		assertEquals(u, "foo");
		
		params.setPrefix("pre-");
		gen.setParams(params);
		u = gen.generateUsername(dn);
		assertEquals(u, "pre-foo");

		params.setPostfix("-post");
		params.setPrefix(null);
		gen.setParams(params);
		u = gen.generateUsername(dn);
		assertEquals(u, "foo-post");
		
		params.setPrefix("pre-${RANDOM}-");
		params.setPostfix(null);
		params.setRandomPrefixLength(6);
		gen.setParams(params);
		u = gen.generateUsername(dn);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("pre-"));
		assertTrue(u.endsWith("-foo"));

		params.setPostfix("-${RANDOM}-post");
		params.setPrefix(null);
		params.setRandomPrefixLength(5);
		gen.setParams(params);
		u = gen.generateUsername(dn);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("foo-"));
		assertTrue(u.endsWith("-post"));		
	}

	public void testUsernameGeneratorUsername() {
		String username = "foo";
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGeneratorParams.USERNAME);
		String u = gen.generateUsername(username);
		assertEquals(u, "foo");
		
		UsernameGeneratorParams params = gen.getParams();
		params.setPrefix("pre-");
		gen.setParams(params);
		u = gen.generateUsername(username);
		assertEquals(u, "pre-foo");

		params.setPostfix("-post");
		params.setPrefix(null);
		gen.setParams(params);
		u = gen.generateUsername(username);
		assertEquals(u, "foo-post");
		
		params.setPrefix("pre-${RANDOM}-");
		params.setPostfix(null);
		params.setRandomPrefixLength(6);
		gen.setParams(params);
		u = gen.generateUsername(username);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("pre-"));
		assertTrue(u.endsWith("-foo"));

		params.setPostfix("-${RANDOM}-post");
		params.setPrefix(null);
		params.setRandomPrefixLength(5);
		gen.setParams(params);
		u = gen.generateUsername(username);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("foo-"));
		assertTrue(u.endsWith("-post"));		
	}

}
