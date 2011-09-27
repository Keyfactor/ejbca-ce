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

import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test of {@link ProfileID}
 * 
 * @version $Id$
 */
public class ProfileIDTest {
	final static Random RANDOM = new Random();
    private static final Logger log = Logger.getLogger(ProfileIDTest.class);
	private class DBTestSometimesFree implements ProfileID.DB {
		private int triesUntilFree = -1;
		public DBTestSometimesFree() {
			// do nothing
		}
		@Override
		public boolean isFree(int i) {
			if ( this.triesUntilFree<0 ) {
				this.triesUntilFree = RANDOM.nextInt(9);
			}
			final boolean isFree = this.triesUntilFree<1;
			this.triesUntilFree--;
			return isFree;
		}
	}
	private class DBTestReal implements ProfileID.DB {
		private final Set<Integer> ids = new HashSet<Integer>();

		public DBTestReal() {
			// do nothing
		}
		@Override
		public boolean isFree(int i) {
			return this.ids.add(Integer.valueOf(i));
		}
	}
	private class DBTestNeverFree implements ProfileID.DB {
		public DBTestNeverFree() {
			// do nothing
		}
		@Override
		public boolean isFree(int i) {
			return false;
		}
	}
	/**
	 * Test that exception is thrown if never free
	 */
	@Test
	public void testNothingFree() {
		log.trace(">testNothingFree()");
		try {
			final int i = ProfileID.getNotUsedID( new DBTestNeverFree() );
			assertTrue("Should not have been possible to generate anything but "+i+" was generated.", false);
		} catch( RuntimeException e ) {
			// NOPMD: this is OK in the test
		}
		log.trace("<testNothingFree()");
	}
	/**
	 * Simulates real behavior. We check that the ID never has been generated before.
	 * Check the log and see that {@link ProfileID#getNotUsedID(ProfileID.DB)} only calls {@link ProfileID.DB#isFree(Integer)} once in almost all test.
	 */
	@Test
	public void testReal() {
		log.trace(">testReal()");
		for ( int i=0; i<0x1000000; i++ ) {
			final int id = ProfileID.getNotUsedID( new DBTestReal() );
			assertTrue( id>0xffff );
		}
		log.trace("<testReal()");
	}
	/**
	 * Test when {@link ProfileID#getNotUsedID(ProfileID.DB)} sometimes return false.
	 */
	@Test
	public void testSometimesFree() {
		log.trace(">testSometimesFree()");
		for ( int i=0; i<0x100; i++ ) {
			final int id = ProfileID.getNotUsedID( new DBTestSometimesFree() );
			assertTrue( id>0xffff );
		}
		log.trace("<testSometimesFree()");
	}
}
