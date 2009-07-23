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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean;
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.ejbca.util.FileTools;

/**
 * Command to restore a catoken keystore from a PKCS12 file.
 * 
 * @see CAAdminSessionBean#restoreCAKeyStore(org.ejbca.core.model.log.Admin, String, byte[], String, String, String, String)
 * @author Markus Kilås
 * @version $Id$
 */
public class CaRestoreKeyStoreCommand extends BaseCaAdminCommand {
	
	/**
	 * Creates a new instance of CaRemoveKeystoresCommand
	 * 
	 * @param args command line arguments
	 */
	public CaRestoreKeyStoreCommand(String[] args) {
		super(args);
	}

	/**
	 * Runs the command
	 * 
	 * @throws IllegalAdminCommandException Error in command args
	 * @throws ErrorAdminCommandException Error running command
	 */
	public void execute() throws IllegalAdminCommandException,
			ErrorAdminCommandException {
		if (args.length < 3 || args.length > 5) {
			String msg = "Usage: CA restorekeystore <CA name> <pkcs12 file> [<signature alias>] [<encryption alias>]\n"
					+ "Leave out both <alias> to use the only available alias or get a list of available aliases "
					+ "if there are more than one.";
			throw new IllegalAdminCommandException(msg);
		}
		try {
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
			getOutputStream().print("Enter keystore password: ");
			// Read the password, but mask it so we don't display it on the console
			ConsolePasswordReader r = new ConsolePasswordReader();
			String kspwd = String.valueOf(r.readPassword());
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
				Enumeration/*String*/ aliases = ks.aliases();
				int length = 0;
				while (aliases.hasMoreElements()) {
					alias = (String) aliases.nextElement();
					getOutputStream().println(
							"Keystore contains alias: " + alias);
					length++;
				}
				if (length > 1) {
					throw new ErrorAdminCommandException("Keystore contains more than one alias, alias must be provided as argument.");
				} else if (length < 1) {
					throw new ErrorAdminCommandException("Keystore does not contains any aliases. It can not be used for a CA.");
				}
				// else alias already contains the only alias, so we can use that
			}
			getCAAdminSession().restoreCAKeyStore(administrator, caName, keystorebytes, kspwd, kspwd, alias, encryptionAlias);
		} catch (ErrorAdminCommandException e) {
			throw e;
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	} // execute
} // CaRestoreKeyStoreCommand
