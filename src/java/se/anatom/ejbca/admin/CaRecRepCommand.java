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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.KeyTools;


/**
 * Receive certificate reply as result of certificate request.
 *
 * @version $Id: CaRecRepCommand.java,v 1.11 2004-10-13 07:14:45 anatom Exp $
 */
public class CaRecRepCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaRecRepCommand
     *
     * @param args command line arguments
     */
    public CaRecRepCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        getOutputStream().println("TODO");
        try {
            if (args.length < 4) {
                getOutputStream().println("Usage: CA recrep <certificate-file> <keystore-file> <storepassword>");
                getOutputStream().println("Used to receive certificates which has been produced as result of sending a certificate request to a CA.");
                return;
            }

            String certfile = args[1];
            String ksfile = args[2];
            String storepwd = args[3];

            getOutputStream().println("Receiving cert reply:");
            getOutputStream().println("Cert reply file: " + certfile);
            getOutputStream().println("Storing KeyStore in: " + ksfile);
            getOutputStream().println("Protected with storepassword: " + storepwd);

            X509Certificate cert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(certfile));
            X509Certificate rootcert = null;
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fis = new FileInputStream(ksfile);
            store.load(fis, storepwd.toCharArray());
            Certificate[] certchain = store.getCertificateChain(privKeyAlias);
            getOutputStream().println("Loaded certificate chain with length " + certchain.length + " with alias 'privateKey'.");
            if (certchain.length == 0) {
                getOutputStream().println("No certificate in chain with alias 'privateKey' in keystore '"+ksfile +"'");
                getOutputStream().println("Reply NOT received!");
                return;                
            }
            if (!CertTools.isSelfSigned((X509Certificate)certchain[0])) {
                getOutputStream().println("Certificate in chain with alias 'privateKey' in keystore '"+ksfile +"' is not selfsigned");
                getOutputStream().println("Reply NOT received!");
                return;
            }
            PrivateKey privKey = (PrivateKey) store.getKey(privKeyAlias, null);
            // check if the private and public keys match
            Signature sign = Signature.getInstance("SHA1WithRSA");
            sign.initSign(privKey);
            sign.update("foooooooooooooooo".getBytes());
            byte[] signature = sign.sign();
            sign.initVerify(cert.getPublicKey());
            sign.update("foooooooooooooooo".getBytes());
            if (sign.verify(signature) == false) {
                getOutputStream().println("Public key in received certificate does not match private key.");
                getOutputStream().println("Reply NOT received!");
                return;
            }
            // Get the certificate chain
            Enumeration aliases = store.aliases();
            ArrayList cacerts = new ArrayList();
            while (aliases.hasMoreElements()) {
                String alias = (String)aliases.nextElement();
                if (!privKeyAlias.equals(alias)) {
                    Certificate cacert = store.getCertificate(alias);
                    cacerts.add(cacert);
                }
            }
            // Create new keyStore
            KeyStore ks = KeyTools.createP12(privKeyAlias, privKey, cert, cacerts);
            FileOutputStream os = new FileOutputStream(ksfile);
            ks.store(os, storepwd.toCharArray());
            getOutputStream().println("Keystore '" + ksfile + "' generated successfully.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    // execute
}
