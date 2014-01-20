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
 
package org.ejbca.ui.cli.ca;

import java.io.FileOutputStream;
import java.util.List;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Exports CA as a PKCS#12 or PKCS#8 file
 *
 * @version $Id$
 */
public class CaExportCACommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "exportca"; }
    @Override
    public String getDescription() { return "Exports CA as a PKCS#12 or PKCS#8 file"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        String signatureKeyAlias = "SignatureKeyAlias";
    	String encryptionKeyAlias = "EncryptionKeyAlias";
        if (args.length < 3) {
			getLogger().info("Description: " + getDescription());
        	getLogger().info("Usage: " + getCommand() + " <CA name> <pkcs12/pkcs8 file> [<signature_key_alias>] [<encryption_key_alias>]");
        	getLogger().info(" Default value for signature_key_alias is \"" + signatureKeyAlias + "\", and for encryption_key_alias" + " is \"" + encryptionKeyAlias + "\".");
        	getLogger().info(" X.509 CAs are exported as PKCS#12 files while for CVC CAs only the private certificate signing key is exported as a PKCS#8 key.");
            getLogger().info(" You will be prompted for keystore password to protect stored keystore, but can optionally specify it on command line using the optional argument '-kspassword yourpwd'.");
        	return;
        }
        try {
            List<String> argsList = CliTools.getAsModifyableList(args);
            int pwdInd = argsList.indexOf("-kspassword");
            String kspwd = null;
            if (pwdInd > -1) {
                kspwd = argsList.get(pwdInd + 1);
                argsList.remove(pwdInd + 1);
                argsList.remove("-kspassword");
            }
            args = argsList.toArray(new String[argsList.size()]); // new args array without the optional switches
        	String caName	= args[1];
            String p12file	= args[2];
            if ( args.length > 3 ) {
            	signatureKeyAlias = args[3];
            }
            if ( args.length > 4 ) {
            	encryptionKeyAlias = args[4];
            }
           
            if (kspwd == null) {
                getLogger().info("Enter keystore password: ");
                // Read the password, but mask it so we don't display it on the console
                kspwd = String.valueOf(System.console().readPassword());                
            } else {
                getLogger().info("Keystore password was supplied on the command line.");                
            }
            
            byte[] keyStoreBytes = ejb.getRemoteSession(CAAdminSessionRemote.class).exportCAKeyStore(getAuthenticationToken(cliUserName, cliPassword), caName, kspwd, kspwd, signatureKeyAlias, encryptionKeyAlias);
            FileOutputStream fos = new FileOutputStream(p12file);
            fos.write(keyStoreBytes);
            fos.close();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
