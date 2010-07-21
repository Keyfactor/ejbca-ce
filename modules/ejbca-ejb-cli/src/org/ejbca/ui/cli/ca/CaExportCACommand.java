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

import javax.ejb.EJB;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Exports CA as a PCKS#12 or PKCS#8 file
 *
 * @version $Id$
 */
public class CaExportCACommand extends BaseCaAdminCommand {

    @EJB
    private CAAdminSessionRemote caAdminSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "exportca"; }
	public String getDescription() { return "Exports CA as a PCKS#12 or PKCS#8 file"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
    	String signatureKeyAlias = "SignatureKeyAlias";
    	String encryptionKeyAlias = "EncryptionKeyAlias";
        if (args.length < 3) {
			getLogger().info("Description: " + getDescription());
        	getLogger().info("Usage: " + getCommand() + " <CA name> <pkcs12/pkcs8 file> [<signature_key_alias>] [<encryption_key_alias>]");
        	getLogger().info("Default values for signature_key_alias is \"" + signatureKeyAlias + "\" and encryption_key_alias" + " is \"" + encryptionKeyAlias + "\".");
        	getLogger().info("X.509 CAs are exported as PKCS#12 files while for CVC CAs only the private certificate signing key is exported as a PKCS#8 key.");
        	return;
        }
        try {
        	String caName	= args[1];
            String p12file	= args[2];
            if ( args.length > 3 ) {
            	signatureKeyAlias = args[3];
            }
            if ( args.length > 4 ) {
            	encryptionKeyAlias = args[4];
            }
           
            getLogger().info("Enter keystore password: ");
            String kspwd = new String(System.console().readPassword());
            
            byte[] keyStoreBytes = caAdminSession.exportCAKeyStore(getAdmin(), caName, kspwd, kspwd, signatureKeyAlias, encryptionKeyAlias);
            FileOutputStream fos = new FileOutputStream(p12file);
            fos.write(keyStoreBytes);
            fos.close();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
