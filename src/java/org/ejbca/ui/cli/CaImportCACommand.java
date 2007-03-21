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
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.Enumeration;

import org.ejbca.util.FileTools;

/**
 * Imports a PKCS12 file and created a new CA from it.
 *
 * @version $Id: CaImportCACommand.java,v 1.3 2007-03-21 13:59:57 jeklund Exp $
 */
public class CaImportCACommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaInfoCommand
     *
     * @param args command line arguments
     */
    public CaImportCACommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 3) {
           String msg = "Usage: CA importca <CA name> <pkcs12 file> [<signature alias>] [<encryption alias>]\n" +
           				"Leave out both <alias> to use the only available alias or get a list of available aliases" +
           				"if there are more than one.\n" +
           				"If no encryption alias is given, the encryption keys will be generated."; 
           throw new IllegalAdminCommandException(msg);
        }
        try {
        	String caName = args[1];
            String p12file = args[2];
            String alias = null;
            String encryptionAlias = null;
            if (args.length > 3) {
            	alias = args[3];
            }
            if (args.length > 4) {
            	encryptionAlias = args[4];
            }
            System.out.print("Enter keystore password: ");
            String kspwd = new BufferedReader(new InputStreamReader(System.in)).readLine();
            // Read old keystore file in the beginning so we know it's good
            byte[] keystorebytes = null;
            keystorebytes = FileTools.readFiletoBuffer(p12file);
            // Import CA from PKCS12 file
            if (alias == null) {
                // First we must find what aliases there is in the pkcs12-file
                KeyStore ks = KeyStore.getInstance("PKCS12","BC");
                FileInputStream fis = new FileInputStream(p12file);
                ks.load(fis, kspwd.toCharArray());
                fis.close();            
                Enumeration aliases = ks.aliases();
                int length = 0;
                while (aliases.hasMoreElements()) {
                    alias = (String)aliases.nextElement();
                    getOutputStream().println("Keystore contains alias: "+alias);
                    length++;
                }
                if (length > 1) {
                	throw new ErrorAdminCommandException("Keystore contains more than one alias, alias must be provided as argument.");
                } else if (length < 1) {
                	throw new ErrorAdminCommandException("Keystore does not contains any aliases. It can not be used for a CA.");
                } 
                // else alias already contains the only alias, so we can use that
            }
            getCAAdminSessionRemote().importCAFromKeyStore(administrator, caName, keystorebytes, kspwd.toCharArray(), kspwd.toCharArray(), alias, encryptionAlias);
          
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
} // CaImportCACommand
