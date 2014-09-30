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
 * AllPrintablePasswordGenerator is a class generating random passwords containing  
 * DigitPasswordGenerator is a class generating random passwords containing 6-8 char 
 * digit passwords. 
 *
 * @version $Id$
 */
public class DigitPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    
	protected static final String NAME = "PWGEN_DIGIT";
    
	public String getName() { return NAME; }
    
    public DigitPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
