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

package org.ejbca.util.passgen;

import java.security.SecureRandom;
import java.util.Random;

/**
 * BasePasswordGenerator is a base class for generating random passwords.
 * Inheriting classes should overload the constants USEDCHARS, MIN_CHARS
 * and MAX_CHARS.
 *
 * @version $Id$
 */
public abstract class BasePasswordGenerator implements IPasswordGenerator {

    private final char[] usedchars;

    protected BasePasswordGenerator(char[] usedchars){
       this.usedchars = usedchars;
    }

	/**
	 * @see org.ejbca.util.passgen.IPasswordGenerator
	 */
	public String getNewPassword(int minlength, int maxlength){
		final int difference = maxlength - minlength;
		final Random ran = new SecureRandom();
		// Calculate the length of password
		int passlen = maxlength;
		if(minlength != maxlength) {
			passlen = minlength + ran.nextInt(difference);
		}
		final char[] password = new char[passlen];
		for (int i=0; i < passlen; i++) {
			password[i] = usedchars[ran.nextInt(usedchars.length)];
		}
		return new String(password);
	}

    public int getNumerOfDifferentChars() { return usedchars.length; }
}
