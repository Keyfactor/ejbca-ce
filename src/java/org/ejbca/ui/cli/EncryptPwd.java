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
 
package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;

/**
 * Implements the password encryption mechanism
 *
 * @version $Id$
 */
public class EncryptPwd extends BaseCommand {
    /**
     * main class
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
    	try {
    		System.out.println("Please note that this encryption does not provide absolute security, it uses a build in key for encryption to keep the password from at least accidentaly beeing known.");
    		System.out.println("Enter word to encrypt: ");
    		InputStreamReader isr = new InputStreamReader ( System.in );
    		BufferedReader br = new BufferedReader ( isr );
    		String s = br.readLine();
    		CertTools.installBCProvider();
    		System.out.println("Encrypting pwd '"+s+"'");
            String enc = StringTools.pbeEncryptStringWithSha256Aes192(s);
            System.out.println(enc);
    	} catch (Exception e) {
    		System.out.println(e.getMessage());
    		//e.printStackTrace();
    		System.exit(-1);
    	}
    }
}
