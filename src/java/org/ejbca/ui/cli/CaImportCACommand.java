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

import org.ejbca.util.FileTools;



/**
 * Imports a PKCS12 file and created a new CA from it.
 *
 * @version $Id: CaImportCACommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
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
        if (args.length < 4) {
           String msg = "Usage: CA importca <CA name> <pkcs12 file> <pwd> [<alias>]\nLeave out <alias> to use sole alias or get a list of available aliases if there are more than one."; 
           throw new IllegalAdminCommandException(msg);
        }
        try {
        	String caName = args[1];
            String p12file = args[2];
            String kspwd = args[3];
            String alias = null;
            if (args.length == 5) {
            	alias = args[4];
            }
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
            getCAAdminSessionRemote().upgradeFromOldCAKeyStore(administrator, caName, keystorebytes, kspwd.toCharArray(), kspwd.toCharArray(), alias);
          
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
