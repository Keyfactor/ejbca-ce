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
 
package org.ejbca.util.passgen;

/**
 * IPasswordGenerator is an interface used to generate passwords used by end entities in EJBCA
 * Usage:
 * <pre>
 *  IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
 *  String pwd = pwdgen.getNewPassword(12, 16);
 * </pre>
 *
 * @version $Id$
 */
public interface IPasswordGenerator {
    
    /**
     *  Method generating a new password for the user and returns a string representation of it.
     * 
     * @param minlength indicates the minimun length of the generated password.
     * @param maxlength indicates the maximum length of the generated password.
     * @return the generated password
     */
    public String getNewPassword(int minlength, int maxlength);

	public String getName();
   
	public int getNumerOfDifferentChars();
}
