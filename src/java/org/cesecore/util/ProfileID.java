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

import java.util.Random;

import org.apache.log4j.Logger;

/**
 * Used to get an ID not already existing in a DB.
 * 
 * @version $Id$
 */
public class ProfileID {
    private static final Logger log = Logger.getLogger(ProfileID.class);
    private static final Random RANDOM = new Random();
    private static final int MIN = 1<<16;
	/**
	 * Callback that is used from caller to check if the generated id can be used, or if we should generate a new one.
	 */
	public static interface DB {
		/**
		 * Test if an ID is not already used in a DB
		 * @param i id to test.
		 * @return true if not already used in DB
		 */
		boolean isFree(int i);
	}
	/**
	 * @param db The {@link DB} implementation.
	 * @return The ID to be used. Always returning >0xffff. IDs <0x10000 are reserved for constant defined in the code.
	 */
	public static int getNotUsedID(final DB db) {
		for ( int i=0; i<10; i++ ) {
		    final int id = getRandomIdNumber();
			if ( db.isFree(id) ) {
				return id;
			}
			log.info("ID "+id+" already exist in DB generating a new random ID.");
		}
		// this throw is indicating an implementation error of the DB class and should never occur. If it does the code must be fixed.
		throw new RuntimeException("Impossible to find a spare ID in the database for the class: "+db.getClass().getCanonicalName());
	}
	
	public static int getRandomIdNumber() {
        return RANDOM.nextInt(Integer.MAX_VALUE-MIN)+MIN;	    
	}
}
