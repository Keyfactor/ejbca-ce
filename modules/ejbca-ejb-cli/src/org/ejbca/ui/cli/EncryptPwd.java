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

import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.StringTools;

/**
 * Implements the password encryption mechanism
 *
 * @version $Id$
 */
public class EncryptPwd extends BaseCommand {
	
	public String getMainCommand() { return null; }
	public String getSubCommand() { return "encryptpwd"; }
	public String getDescription() { return "Encrypts a password to avoid accidental reading"; }

	public void execute(String[] args) throws ErrorAdminCommandException {
    	try {
    		getLogger().info("Please note that this encryption does not provide absolute security, it uses a build in key for encryption to keep the password from at least accidentaly beeing known.");
    		getLogger().info("Enter word to encrypt: ");
    		String s = String.valueOf(System.console().readPassword());
    		CryptoProviderTools.installBCProvider();
    		getLogger().info("Encrypting pwd...");
            String enc = StringTools.pbeEncryptStringWithSha256Aes192(s);
            getLogger().info(enc);
    	} catch (Exception e) {
    		getLogger().error(e.getMessage());
    		System.exit(-1); // NOPMD
    	}
    }
}
