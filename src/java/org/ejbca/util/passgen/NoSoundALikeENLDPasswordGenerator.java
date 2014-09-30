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
 * This class allows all letters and digits except those that sound similar in english like aj and eg.
 *
 * @version $Id$
 */
public class NoSoundALikeENLDPasswordGenerator extends BasePasswordGenerator {
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0',
    																		'q','Q','w','W','r','R','t','T',
    																		'y','Y','u','U','i','I','o','O','p','P',
    																		's','S','d','D','f','F','h','H',
    																		'k','K','l','L','z','Z','x','X','c','C',
    																		'v','V','b','B','n','N','m','M'};
        
	protected static final String NAME = "PWGEN_NOSOUNDALIKEENLD";
    
	public String getName() { return NAME; }
	
    public NoSoundALikeENLDPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
