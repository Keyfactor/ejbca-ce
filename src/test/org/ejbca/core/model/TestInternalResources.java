package org.ejbca.core.model;

import junit.framework.TestCase;

public class TestInternalResources extends TestCase {

	

	protected void setUp() throws Exception {		
		super.setUp();
	}

	public void testGetLocalizedMessageString() {
		InternalResources intres = InternalResourcesTestClass.getInstance();
		
		assertTrue(intres.getLocalizedMessage("raadmin.testmsg"),intres.getLocalizedMessage("raadmin.testmsg").equals("Test SV"));
		
	}

	public void testGetLocalizedMessageStringObject() {
		InternalResources intres = InternalResourcesTestClass.getInstance();
		
		String res = intres.getLocalizedMessage("raadmin.testparams",new Long(1), new Integer(3), "hi", new Boolean(true), "bye");
		
		assertTrue(res,res.equals("Test 1 3 hi true bye message 1"));
	}

	public void testGetLocalizedMessageStringObjectWithNull() {
		InternalResources intres = InternalResourcesTestClass.getInstance();
		
		String res = intres.getLocalizedMessage("raadmin.testparams",null, new Integer(3), null, new Boolean(true), "bye");
		
		assertTrue(res,res.equals("Test  3  true bye message "));
	}
}
