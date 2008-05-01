/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.protect;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public interface Protectable {

	/** Creates and returns the hash code created from the object, the version
	 * parameter can be used to handle upgrades to the class, since the hash must 
	 * always be the same, even if this method is caled one year later.
	 * 
	 * @param dataVersion version of class/hash requested.
	 * @return String hash value
	 */
	public String getHash(int hashVersion) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException;
	
	/** The same as above, but returns the hash value for the current version of the object
	 * 
	 * @return hash value
	 */
	public String getHash() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException;
	
	public int getHashVersion();
	
	/** Returns the String form of the primary key for the database table that 
	 * this object is stored in.
	 * 
	 * @return String Stringform of primary database key, used as key in the protection database table.
	 */
	public String getDbKeyString();
	
	/** Returns a unique type string for these kinds of objects, for example LOGENTRY.
	 * 
	 * @return String can be anything, as long as it is always the same.
	 */
	public String getEntryType();
}
