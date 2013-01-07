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
 * Caching of CA SubjectDN hashes that maps to real CAId.
 * 
 * In some border cases the content of the CA certificate's subjectDN is not
 * what was used to generate the CA Id and therefore we often want to lookup
 * this "real" value.
 * 
 * @version $Id$
 */
public final class CACacheHelper {

    /** Caching of CA IDs with CA cert DN hash as ID */
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
}
