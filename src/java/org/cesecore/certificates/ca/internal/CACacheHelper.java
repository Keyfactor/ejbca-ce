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
package org.cesecore.certificates.ca.internal;

import java.util.HashMap;
import java.util.Map;


/**
 * Class Holding cache variables. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it only holds variables actually, does nothing. All updating etc is done by the user.
 * 
 * Based on EJBCA version: CaHelperCache.java 10862 2010-12-14 16:07:19Z anatom
 * 
 * @version $Id: CACacheHelper.java 146 2011-01-25 11:59:11Z tomas $
 */
public final class CACacheHelper {

    /**
     * help variable used to control that CA info update (read from database)
     * isn't performed to often.
     */
    private static volatile long lastCACacheUpdateTime = -1;

    /**
     * Caching of CA IDs with CA cert DN hash as ID
     */
    protected static volatile Map<Integer, Integer> caIdToCaCertHash = new HashMap<Integer, Integer>();


	private CACacheHelper() {
		// Do nothing
	}

	public static Integer getCaCertHash(Integer caid) {
		return caIdToCaCertHash.get(Integer.valueOf(caid));
	}

	public static void putCaCertHash(Integer caid, Integer caCertHash) {
		caIdToCaCertHash.put(caid, caCertHash);
	}
	public static long getLastCACacheUpdateTime() {
		return lastCACacheUpdateTime;
	}


	public static void setLastCACacheUpdateTime(final long lastCACacheUpdateTime) {
		CACacheHelper.lastCACacheUpdateTime = lastCACacheUpdateTime;
	}

}
