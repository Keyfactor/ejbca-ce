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
import java.io.FileOutputStream;
import java.io.InputStreamReader;

/**
 * Imports a PKCS12 file and created a new CA from it.
 *
 * @version $Id: CaExportCACommand.java,v 1.1 2007-03-21 13:59:57 jeklund Exp $
 */
public class CaExportCACommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaInfoCommand
     *
     * @param args command line arguments
     */
    public CaExportCACommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String signatureKeyAlias = "SignatureKeyAlias";
    	String encryptionKeyAlias = "EncryptionKeyAlias";
        if (args.length < 3) {
           String msg = "Usage: CA exportca <CA name> <pkcs12 file> [<signature_key_alias>] [<encryption_key_alias>]\n" +
           				"Default values for signature_key_alias is \"" + signatureKeyAlias + "\" and encryption_key_alias" +
           				" is \"" + encryptionKeyAlias + "\".";
           throw new IllegalAdminCommandException(msg);
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
            System.out.print("Enter keystore password: ");
            String kspwd = new BufferedReader(new InputStreamReader(System.in)).readLine();
            
		    if ( !getCAAdminSessionRemote().isKeyStorePassword(administrator, kspwd) ) {
		    	throw new IllegalArgumentException("Keystore password does not match user-supplied password.");
		    }
            byte[] keyStoreBytes = getCAAdminSessionRemote().exportCAKeyStore(administrator, caName, kspwd.toCharArray(), kspwd.toCharArray(), signatureKeyAlias, encryptionKeyAlias);
            FileOutputStream fos = new FileOutputStream(p12file);
            fos.write(keyStoreBytes);
            fos.close();
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
