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

package org.ejbca.core.model.log;

import java.security.Key;
import java.security.cert.Certificate;

/**
 * @version $Id$
 * @deprecated
 */
public interface IProtectedLogToken {

	public static final int TYPE_CA       = 1;
	public static final int TYPE_SYM_KEY  = 2;
	public static final int TYPE_ASYM_KEY = 3;
	public static final int TYPE_NONE     = 4;

	public abstract String getProtectionAlgorithm();

	public abstract int getType();

	public abstract Certificate getTokenCertificate();

	public abstract Key getTokenProtectionKey();

	public abstract int getCAId();

	/**
	 * @return an unique identifier for this ProtectedLogToken. Based on hashing the Key.
	 */
	public abstract int getIdentifier();

	/**
	 *  Creates a signature based on the tokens properties.
	 */
	public abstract byte[] protect(byte[] data);

	/**
	 *  Verifies a signature based on the tokens properties.
	 *  @return true if the signture matches
	 */
	public abstract boolean verify(byte[] data, byte[] signature);

}