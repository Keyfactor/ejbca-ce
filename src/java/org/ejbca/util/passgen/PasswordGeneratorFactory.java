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

import java.util.ArrayList;
import java.util.Collection;

/**
 * Factory class creating PasswordGenerators.
 * Usage:
 * <pre>
 *  IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
 *  String pwd = pwdgen.getNewPassword(12, 16);
 * </pre>
 *
 * @version $Id$
 */
public class PasswordGeneratorFactory {
    
    
    public static final String PASSWORDTYPE_DIGITS                       = DigitPasswordGenerator.NAME;
    public static final String PASSWORDTYPE_LETTERSANDDIGITS             = LettersAndDigitsPasswordGenerator.NAME;
	public static final String PASSWORDTYPE_ALLPRINTABLE                 = AllPrintableCharPasswordGenerator.NAME;	
	public static final String PASSWORDTYPE_NOLOOKALIKELD                 = NoLookALikeLDPasswordGenerator.NAME;	
	public static final String PASSWORDTYPE_NOSOUNDALIKEENLD                 = NoSoundALikeENLDPasswordGenerator.NAME;	
	public static final String PASSWORDTYPE_NOTALIKEENLD                 = NoLookOrSoundALikeENLDPasswordGenerator.NAME;	
    
    static final IPasswordGenerator[] classes = { new DigitPasswordGenerator(),
    	                                          new LettersAndDigitsPasswordGenerator(),
    	                                          new AllPrintableCharPasswordGenerator(),
    	                                          new NoLookALikeLDPasswordGenerator(),
    	                                          new NoSoundALikeENLDPasswordGenerator(),
    	                                          new NoLookOrSoundALikeENLDPasswordGenerator()};
    
    /**
     *  Method returning an instance of the specified IPasswordGenerator class.
     *      
     *  @param type should be on of the PasswordGeneratorFactory constants.
     */
    
    public static IPasswordGenerator getInstance(String type){
    	IPasswordGenerator ret = null;
    	for (int i=0; i<classes.length; i++) {
    		if (classes[i].getName().equals(type)) {
    			ret = classes[i];
    		}
    	}
		return ret;
    }

	public static Collection<String> getAvailablePasswordTypes() {
		ArrayList<String> al = new ArrayList<String>();
    	for (int i=0; i<classes.length; i++) {
    		al.add(classes[i].getName());
    	}
		return al;
	}
   
}
