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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;
import java.util.List;

import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Restore a CA token keystore from a PKCS12 file.
 * 
 * @version $Id$
 */
public class CaRestoreKeyStoreCommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "restorekeystore"; }
    @Override
    public String getDescription() { return "Restore a CA token keystore from a PKCS12 file."; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        
		if (args.length < 3 || args.length > 7) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage: " + getCommand() + " <CA name> <pkcs12 file> [<signature alias>] [<encryption alias>]");
    		getLogger().info(" Leave out both <.. alias> to use the only available alias or get a list of available aliases ");
    		getLogger().info(" if there are more than one.");
            getLogger().info(" You will be prompted for keystore password, but can optionally specify it on command line using the optional argument '-kspassword yourpwd'.");
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
			String caName = args[1];
			// Import soft keystore
			String p12file = args[2];
			String alias = null;
			String encryptionAlias = null;
			if (args.length > 3) {
				alias = args[3];
			}
			if (args.length > 4) {
				encryptionAlias = args[4];
			}
			if (kspwd == null) {
	            getLogger().info("Enter keystore password: ");
	            // Read the password, but mask it so we don't display it on the console
	            kspwd = String.valueOf(System.console().readPassword());			    
			} else {
                getLogger().info("Keystore password was supplied on the command line.");			    
			}
			// Read old keystore file in the beginning so we know it's good
			byte[] keystorebytes = null;
			keystorebytes = FileTools.readFiletoBuffer(p12file);
			// Import CA from PKCS12 file
			if (alias == null) {
				// First we must find what aliases there is in the pkcs12-file
				KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
				FileInputStream fis = new FileInputStream(p12file);
				ks.load(fis, kspwd.toCharArray());
				fis.close();
				Enumeration<String> aliases = ks.aliases();
				int length = 0;
				while (aliases.hasMoreElements()) {
					alias = aliases.nextElement();
					getLogger().info("Keystore contains alias: " + alias);
					length++;
				}
				if (length > 1) {
					throw new ErrorAdminCommandException("Keystore contains more than one alias, alias must be provided as argument.");
				} else if (length < 1) {
					throw new ErrorAdminCommandException("Keystore does not contains any aliases. It can not be used for a CA.");
				}
				// else alias already contains the only alias, so we can use that
			}
			ejb.getRemoteSession(CAAdminSessionRemote.class).restoreCAKeyStore(getAuthenticationToken(cliUserName, cliPassword), caName, keystorebytes, kspwd, kspwd, alias, encryptionAlias);
		} catch (ErrorAdminCommandException e) {
			throw e;
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
