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
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Enumeration;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.FileTools;

/**
 * Imports a keystore and creates a new X509 CA from it
 *
 * @version $Id$
 */
public class CaImportCACommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importca"; }
	public String getDescription() { return "Imports a keystore and creates a new X509 CA from it"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
    	if (args.length < 3) {
    		getLogger().info("Description: " + getDescription());
    		getLogger().info("Usage 1: " + getCommand() + " <CA name> <pkcs12 file> [<signature alias>] [<encryption alias>]");
    		getLogger().info(" Leave out both <alias> to use the only available alias or get a list of available aliases");
    		getLogger().info(" if there are more than one.");
    		getLogger().info(" If no encryption alias is given, the encryption keys will be generated.");
    		getLogger().info("Usage2: CA " + getCommand() + " <CA name> <catokenclasspath> <catokenpassword> <catokenproperties> <ca-certificate-file>");
    		getLogger().info(" catokenclasspath: example org.ejbca.core.model.ca.catoken.PKCS11CAToken for PKCS11 HSMs.");
    		getLogger().info(" catokenproperties: a file were you define key name, password and key alias for the HSM. Same as the Hard CA Token Properties in Admin gui.");
    		getLogger().info(" ca-certificate-file: a file with the CA-certificates in. One or more CA-certificates, with this CAs certificate first, and others following in certificate chain order.");
    		return;
        }
    	
    	CryptoProviderTools.installBCProvider();
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
                getLogger().info("Enter keystore password: ");
                // Read the password, but mask it so we don't display it on the console
                String kspwd = String.valueOf(System.console().readPassword());
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
                    Enumeration<String> aliases = ks.aliases();
                    int length = 0;
                    while (aliases.hasMoreElements()) {
                        alias = (String)aliases.nextElement();
                        getLogger().info("Keystore contains alias: "+alias);
                        length++;
                    }
                    if (length > 1) {
                    	throw new ErrorAdminCommandException("Keystore contains more than one alias, alias must be provided as argument.");
                    } else if (length < 1) {
                    	throw new ErrorAdminCommandException("Keystore does not contains any aliases. It can not be used for a CA.");
                    } 
                    // else alias already contains the only alias, so we can use that
                }
                ejb.getCAAdminSession().importCAFromKeyStore(getAdmin(), caName, keystorebytes, kspwd, kspwd, alias, encryptionAlias);        		
        	} else {
        		// Import HSM keystore
                // "Usage2: CA importca <CA name> <catokenclasspath> <catokenpassword> <catokenproperties> <ca-certificate-file>\n" +
        		String tokenclasspath = args[2];
        		String tokenpwd = args[3];
        		String catokenproperties = new String(FileTools.readFiletoBuffer(args[4]));
        		Collection<Certificate> cacerts = CertTools.getCertsFromPEM(args[5]);
        		Certificate[] cacertarray = cacerts.toArray(new Certificate[0]);
        		ejb.getCAAdminSession().importCAFromHSM(getAdmin(), caName, cacertarray, tokenpwd, tokenclasspath, catokenproperties);
        	}
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
