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
 
package se.anatom.ejbca.util.passgen;

/**
 * AllPrintablePasswordGenerator is a class generating random passwords containing  
 * DigitPasswordGenerator is a class generating random passwords containing 6-8 char 
 * digit passwords. 
 *
 * @version $Id: DigitPasswordGenerator.java,v 1.4 2004-04-16 07:39:01 anatom Exp $
 */
public class DigitPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    

    
    public DigitPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
