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
 * @version $Id: CaMakeReqCommand.java,v 1.9 2004-03-04 11:18:39 anatom Exp $
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


        
        System.out.println("Generating cert request (and keystore):");
        System.out.println("DN: " + dn);
        System.out.println("Keysize: " + keysize);
        System.out.println("RootCA cert file: " + rootfile);
        System.out.println("Storing CertificationRequest in: " + reqfile);
        System.out.println("Storing KeyStore in: " + ksfile);
        System.out.println("Protected with storepassword: " + storepwd);

        try {
            // Read in RootCA certificate
            Collection rootcerts = CertTools.getCertsFromPEM(new FileInputStream(rootfile));

            // Generate keys
            System.out.println("Generating keys, please wait...");

            KeyPair rsaKeys = KeyTools.genKeys(keysize);

            // Create selfsigned cert...
            X509Certificate selfcert = CertTools.genSelfCert(dn, 365, null, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);

            // Create certificate request
            makeCertRequest(dn, rsaKeys, reqfile);

            // Create keyStore
            KeyStore ks = KeyTools.createP12(privKeyAlias, rsaKeys.getPrivate(), selfcert, rootcerts);

            FileOutputStream os = new FileOutputStream(ksfile);
            ks.store(os, storepwd.toCharArray());
            System.out.println("Keystore '"+ksfile+"' generated successfully.");
         
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute


    // execute
}
