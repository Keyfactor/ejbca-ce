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
 
package se.anatom.ejbca.admin;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;


/**
 * Generates keys and creates a keystore (PKCS12) to be used by the CA.
 *
 * @version $Id: CaMakeReqCommand.java,v 1.11 2004-10-13 07:14:46 anatom Exp $
 */
public class CaMakeReqCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaMakeReqCommand
     *
     * @param args command line arguments
     */
    public CaMakeReqCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

        if (args.length < 7) {
            String msg = "Usage: CA makereq <DN> <keysize> <rootca-certificate> <request-file> <keystore-file> <storepassword>";
            msg += "\nGenerates a certification request for a subCA for sending to a RootCA.";
            msg += "\nrootca-certificates is a file with one or more PEM-certificates, ordered so the RootCA is last.";
            throw new IllegalAdminCommandException(msg);
        }

        String dn = args[1];
        int keysize = Integer.parseInt(args[2]);
        String rootfile = args[3];
        String reqfile = args[4];
        String ksfile = args[5];
        String storepwd = args[6];


        
        getOutputStream().println("Generating cert request (and keystore):");
        getOutputStream().println("DN: " + dn);
        getOutputStream().println("Keysize: " + keysize);
        getOutputStream().println("RootCA cert file: " + rootfile);
        getOutputStream().println("Storing CertificationRequest in: " + reqfile);
        getOutputStream().println("Storing KeyStore in: " + ksfile);
        getOutputStream().println("Protected with storepassword: " + storepwd);

        try {
            // Read in RootCA certificate
            Collection rootcerts = CertTools.getCertsFromPEM(new FileInputStream(rootfile));

            // Generate keys
            getOutputStream().println("Generating keys, please wait...");

            KeyPair rsaKeys = KeyTools.genKeys(keysize);

            // Create selfsigned cert...
            X509Certificate selfcert = CertTools.genSelfCert(dn, 365, null, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);

            // Create certificate request
            makeCertRequest(dn, rsaKeys, reqfile);

            // Create keyStore
            KeyStore ks = KeyTools.createP12(privKeyAlias, rsaKeys.getPrivate(), selfcert, rootcerts);

            FileOutputStream os = new FileOutputStream(ksfile);
            ks.store(os, storepwd.toCharArray());
            getOutputStream().println("Keystore '"+ksfile+"' generated successfully.");
         
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute


    // execute
}
