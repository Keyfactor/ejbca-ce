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
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;
import se.anatom.ejbca.util.KeyTools;


/**
 * Creates a new root certificate with new validity, using the same key.
 *
 * @version $Id: CaRolloverSubCommand.java,v 1.11 2004-10-13 07:14:46 anatom Exp $
 */
public class CaRolloverSubCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaRolloverSubCommand
     *
     * @param args command line arguments
     */
    public CaRolloverSubCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 5) {
                getOutputStream().println(
                    "Usage: CA rolloversub <validity-days> <keystore filename> <storepassword> <certrequest filename>");
                getOutputStream().println(
                    "Rolloversub is used to generate a new subCA certificate using an existing keypair. This updates the current subCA keystore.");

                return;
            }

            int validity = Integer.parseInt(args[1]);
            String ksfilename = args[2];
            String storepwd = args[3];
            String reqfile = args[4];

            // Load keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            InputStream is = new FileInputStream(ksfilename);
            keyStore.load(is, storepwd.toCharArray());

            // Get old certificate chain
            Certificate[] chain = KeyTools.getCertChain(keyStore, privKeyAlias);

            if (chain.length > 2) {
                getOutputStream().println(
                    "Certificate chain too long, this keystore was not generated with EJBCA?");

                return;
            }

            X509Certificate rootcert = (X509Certificate) chain[chain.length - 1];

            if (!CertTools.isSelfSigned(rootcert)) {
                getOutputStream().println("Root certificate is not self signed???");

                return;
            }

            X509Certificate cacert = null;

            if (chain.length > 1) {
                cacert = (X509Certificate) chain[0];
            }

            if (cacert == null) {
                getOutputStream().println(
                    "No subCA certificate found in keystore, this is not a subCA or keystore was not generated with EJBCA.");

                return;
            }

            String subjectDN = CertTools.getSubjectDN(cacert);
            getOutputStream().println("Generating new certificate request for CA with DN '" + subjectDN +
                "'.");

            // Get private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(privKeyAlias, privateKeyPass);

            if (privateKey == null) {
                getOutputStream().println("No private key with alias '" + privKeyAlias +
                    "' in keystore, this keystore was not generated with EJBCA?");

                return;
            }

            // Make a KeyPair
            KeyPair keyPair = new KeyPair(cacert.getPublicKey(), privateKey);

            // verify that the old and new keyidentifieras are the same
            String policyId = CertTools.getCertificatePolicyId(cacert, 0);
            X509Certificate newselfcert = CertTools.genSelfCert(subjectDN, validity, policyId,
                    privateKey, cacert.getPublicKey(), true);
            String oldKeyId = Hex.encode(CertTools.getSubjectKeyId(cacert));
            String newKeyId = Hex.encode(CertTools.getSubjectKeyId(newselfcert));
            getOutputStream().println("Old key id: " + oldKeyId);

            if (oldKeyId == null) {
                getOutputStream().println("Old certificate does not contain SubjectKeyIdentifier.");
                getOutputStream().println("This is recommended, but decided by your CA.");
                getOutputStream().println("Continuing...");
            } else {
                getOutputStream().println("New key id: " + newKeyId);

                if (oldKeyId.compareTo(newKeyId) != 0) {
                    getOutputStream().println(
                        "Old key identifier and new key identifieras does not match, have the key pair changed?");
                    getOutputStream().println("Unable to rollover subCA.");

                    return;
                }
            }

            // Generate the new certificate request
            makeCertRequest(subjectDN, keyPair, reqfile);

            getOutputStream().println(
                "Submit certificare request to RootCA and when receiving reply run 'ca recrep'.");
        } catch (Exception e) {
            e.printStackTrace();
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
