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
 * AllPrintablePasswordGenerator is a class generating random passwords containing all printable 
 * english characters.
 *
 * @version $Id: AllPrintableCharPasswordGenerator.java,v 1.3 2004-04-16 07:39:01 anatom Exp $
 */
public class AllPrintableCharPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0','+','!','#','$',
    	                                                      '%','&','/','(',')','=','?','q','Q','w','W','e','E','r',
    	                                                      'R','t','T','y','Y','u','U','i','I','o','O','p','P','*','a',
    	                                                      'A','s','S','d','D','f','F','g','G','h','H','j','J','k','K',
    	                                                      'l','L','z','Z','x','X','c','C','v','V','b','B','n','N','m',
    	                                                      'M'};
        
    public AllPrintableCharPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
