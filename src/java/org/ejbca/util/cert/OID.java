/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.cert;

import java.util.StringTokenizer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Utilities for to be used on an Object Identifier (OID).
 * 
 * @author Lars Silvén
 * @version $Id$
 */
public class OID {
	/**
	 * Tests if the beginning of a string identifies an OID.
	 * @param s the string to be tested.
	 * @return true if s is a OID or if first part of s is a OID and the first character after the OID is '.' in s.
	 */
	public static boolean isStartingWithValidOID(String s) {
		if ( s==null || s.length()<1 ) {
			return false;
		}
		final StringTokenizer st = new StringTokenizer(s, ".");
		String sOID = "";
		while( st.hasMoreTokens() ) {
			final String token = st.nextToken();
			try {
				Integer.parseInt(token);
			} catch ( NumberFormatException e ) {
				break;
			}
			if ( sOID.length()>0 ) {
				sOID += ".";
			}
			sOID+=token;
		}
		try {
			new ASN1ObjectIdentifier(sOID);
		} catch ( IllegalArgumentException e ) {
			return false;
		}
		return true;
	}
}
