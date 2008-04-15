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
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Enumeration;

import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;

/**
 * Imports a PKCS12 file and created a new CA from it.
 *
 * @version $Id: CaImportCACommand.java,v 1.6 2008-04-15 01:11:27 anatom Exp $
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
           String msg = "Usage 1: CA importca <CA name> <pkcs12 file> [<signature alias>] [<encryption alias>]\n" +
           				"Leave out both <alias> to use the only available alias or get a list of available aliases" +
           				"if there are more than one.\n" +
           				"If no encryption alias is given, the encryption keys will be generated.\n" + 
                        "Usage2: CA importca <CA name> <catokenclasspath> <catokenpassword> <catokenproperties> <ca-certificate-file>\n" +
           				"catokenclasspath: example org.ejbca.core.model.ca.catoken.NFastCAToken for nCipher, org.ejbca.core.model.ca.catoken.PKCS11CAToken for PKCS11.\n" +
           				"catokenproperties is a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in Admin gui.\n" +
        				"ca-certificate-file is a file with the CA-certificates in. One or more CA-certificates, with this CAs certificate first, and others following in certificate chain order.";
           throw new IllegalAdminCommandException(msg);
        }
        try {
        	String caName = args[1];
        	if (args.length < 6) {
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
                getCAAdminSessionRemote().importCAFromKeyStore(administrator, caName, keystorebytes, kspwd, kspwd, alias, encryptionAlias);        		
        	} else {
        		// Import HSM keystore
                // "Usage2: CA importca <CA name> <catokenclasspath> <catokenpassword> <catokenproperties> <ca-certificate-file>\n" +
        		String tokenclasspath = args[2];
        		String tokenpwd = args[3];
        		String catokenproperties = new String(FileTools.readFiletoBuffer(args[4]));
        		Collection cacerts = CertTools.getCertsFromPEM(args[5]);
        		Certificate[] cacertarray = (Certificate[])cacerts.toArray(new Certificate[0]);
        		getCAAdminSessionRemote().importCAFromHSM(administrator, caName, cacertarray, tokenpwd, tokenclasspath, catokenproperties);
        	}
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
} // CaImportCACommand
