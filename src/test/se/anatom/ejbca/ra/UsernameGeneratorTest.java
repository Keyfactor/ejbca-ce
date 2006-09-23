package se.anatom.ejbca.ra;

import junit.framework.TestCase;

import org.ejbca.core.model.ra.UsernameGenerator;

public class UsernameGeneratorTest extends TestCase {

	/*
	 * Test method for 'org.ejbca.core.model.ra.UsernameGenerator.UsernameGenerator(String)'
	 */
	public void testUsernameGeneratorRandom() {
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGenerator.RANDOM);
		String u = gen.generateUsername();
		assertEquals(u.length(), 12);
		
		gen.setRandomNameLength(5);
		u = gen.generateUsername();
		assertEquals(u.length(), 5);
		
		gen.setPrefix("foo-");
		u = gen.generateUsername();
		assertEquals(u.length(), 9);
		assertTrue(u.startsWith("foo-"));

		gen.setPostfix("-foo");
		gen.setPrefix(null);
		u = gen.generateUsername();
		assertEquals(u.length(), 9);
		assertTrue(u.endsWith("-foo"));
		
		gen.setPrefix("foo-${RANDOM}");
		gen.setPostfix(null);
		gen.setRandomPrefixLength(6);
		u = gen.generateUsername();
		assertEquals(u.length(), 15);
		assertTrue(u.startsWith("foo-"));

		gen.setPostfix("${RANDOM}-foo");
		gen.setPrefix(null);
		gen.setRandomPrefixLength(5);
		u = gen.generateUsername();
		assertEquals(u.length(), 14);
		assertTrue(u.endsWith("-foo"));
		
		gen.setPrefix("foo-");
		u = gen.generateUsername();
		assertEquals(u.length(), 18);
		assertTrue(u.endsWith("-foo"));
		assertTrue(u.startsWith("foo-"));
	}

	public void testUsernameGeneratorDN() {
		String dn = "C=SE, O=FooO, UID=foo, CN=bar";
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGenerator.DN);
		String u = gen.generateUsername(dn);
		assertEquals(u, "bar");
		
		gen.setDNGeneratorComponent("UID");
		u = gen.generateUsername(dn);
		assertEquals(u, "foo");
		
		gen.setPrefix("pre-");
		u = gen.generateUsername(dn);
		assertEquals(u, "pre-foo");

		gen.setPostfix("-post");
		gen.setPrefix(null);
		u = gen.generateUsername(dn);
		assertEquals(u, "foo-post");
		
		gen.setPrefix("pre-${RANDOM}-");
		gen.setPostfix(null);
		gen.setRandomPrefixLength(6);
		u = gen.generateUsername(dn);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("pre-"));
		assertTrue(u.endsWith("-foo"));

		gen.setPostfix("-${RANDOM}-post");
		gen.setPrefix(null);
		gen.setRandomPrefixLength(5);
		u = gen.generateUsername(dn);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("foo-"));
		assertTrue(u.endsWith("-post"));		
	}

	public void testUsernameGeneratorUsername() {
		String username = "foo";
		UsernameGenerator gen = UsernameGenerator.getInstance(UsernameGenerator.USERNAME);
		String u = gen.generateUsername(username);
		assertEquals(u, "foo");
		
		gen.setPrefix("pre-");
		u = gen.generateUsername(username);
		assertEquals(u, "pre-foo");

		gen.setPostfix("-post");
		gen.setPrefix(null);
		u = gen.generateUsername(username);
		assertEquals(u, "foo-post");
		
		gen.setPrefix("pre-${RANDOM}-");
		gen.setPostfix(null);
		gen.setRandomPrefixLength(6);
		u = gen.generateUsername(username);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("pre-"));
		assertTrue(u.endsWith("-foo"));

		gen.setPostfix("-${RANDOM}-post");
		gen.setPrefix(null);
		gen.setRandomPrefixLength(5);
		u = gen.generateUsername(username);
		assertEquals(u.length(), 14);
		assertTrue(u.startsWith("foo-"));
		assertTrue(u.endsWith("-post"));		
	}

}
