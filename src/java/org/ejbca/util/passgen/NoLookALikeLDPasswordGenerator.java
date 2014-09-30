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
 * This class allows all letters and digits except those that look similar like 0O and l1I.
 *
 * @version $Id$
 */
public class NoLookALikeLDPasswordGenerator extends BasePasswordGenerator {
    
    private static final char[] USEDCHARS = {'2','3','4','5','6','7','8','9',
    	                                                      'q','Q','w','W','e','E','r',
    	                                                      'R','t','T','y','Y','u','U','i','o','p','P','a',
    	                                                      'A','s','S','d','D','f','F','g','G','h','H','j','J','k','K',
    	                                                      'L','z','Z','x','X','c','C','v','V','b','B','n','N','m',
    	                                                      'M'};
        
	protected static final String NAME = "PWGEN_NOLOOKALIKELD";
    
	public String getName() { return NAME; }
	
    public NoLookALikeLDPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
