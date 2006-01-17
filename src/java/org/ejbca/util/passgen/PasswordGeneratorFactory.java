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

/**
 * Factory class creating PasswordGenerators.
 *
 * @version $Id: PasswordGeneratorFactory.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class PasswordGeneratorFactory {
    
    
    public static final int PASSWORDTYPE_DIGITS                       = 0;
    public static final int PASSWORDTYPE_LETTERSANDDIGITS             = 1;
	public static final int PASSWORDTYPE_ALLPRINTABLE                 = 2;	
    
    static final IPasswordGenerator[] classes = { new DigitPasswordGenerator(),
    	                                          new LettersAndDigitsPasswordGenerator(),
    	                                          new AllPrintableCharPasswordGenerator()};
   
    
    /**
     *  Method returning an instance of the specified IPasswordGenerator class.
     *      
     *  @param type should be on of the PasswordGeneratorFactory constants.
     */
    
    public static IPasswordGenerator getInstance(int type){
       return classes[type];	    	
    }
   
}
