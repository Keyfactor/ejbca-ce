package se.anatom.ejbca.admin;

import java.io.*;
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
 * @version $Id: CaRolloverRootCommand.java,v 1.7 2003-07-24 08:43:29 anatom Exp $
 */
public class CaRolloverRootCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaRolloverRootCommand
     *
     * @param args command line arguments
     */
    public CaRolloverRootCommand(String[] args) {
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
            if (args.length < 4) {
                System.out.println(
                    "Usage: CA rolloverroot <validity-days> <keystore filename> <storepassword>");
                System.out.println(
                    "Rolloverroot is used to generate a new RootCA certificate using an existing keypair. This updates the current RootCA keystore.");

                return;
            }

            int validity = Integer.parseInt(args[1]);
            String filename = args[2];
            String storepwd = args[3];

            // Get old root certificate
            Certificate[] chain = getCertChain();

            if (chain.length > 2) {
                System.out.println(
                    "Certificate chain too long, this P12 was not generated with EJBCA?");

                return;
            }

            X509Certificate rootcert = (X509Certificate) chain[chain.length - 1];

            if (!CertTools.isSelfSigned(rootcert)) {
                System.out.println("Root certificate is not self signed???");

                return;
            }

            X509Certificate cacert = null;

            if (chain.length > 1) {
                cacert = (X509Certificate) chain[chain.length - 2];
            }

            // Get private key
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            InputStream is = new FileInputStream(filename);
            keyStore.load(is, storepwd.toCharArray());

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(privKeyAlias, privateKeyPass);

            if (privateKey == null) {
                System.out.println("No private key with alias '" + privKeyAlias +
                    "' in keystore, this keystore was not generated with EJBCA?");

                return;
            }

            // Generate the new root certificate
            String policyId = CertTools.getCertificatePolicyId(rootcert);
            System.out.println("Certificate policy Id is '" + policyId + "'.");

            X509Certificate newrootcert = CertTools.genSelfCert(CertTools.getSubjectDN(rootcert),
                    validity, policyId, privateKey, rootcert.getPublicKey(), true);

            // verify that the old and new keyidentifieras are the same
            String oldKeyId = Hex.encode(CertTools.getAuthorityKeyId(rootcert));
            String newKeyId = Hex.encode(CertTools.getAuthorityKeyId(newrootcert));
            System.out.println("Old key id: " + oldKeyId);
            System.out.println("New key id: " + newKeyId);

            if (oldKeyId.compareTo(newKeyId) != 0) {
                System.out.println(
                    "Old key identifier and new key identifieras does not match, have the key pair changed?");
                System.out.println("Unable to rollover Root CA.");

                return;
            }

            // Create the new PKCS12 file
            KeyStore ks = KeyTools.createP12(privKeyAlias, privateKey, newrootcert, cacert);
            FileOutputStream os = new FileOutputStream(filename);
            ks.store(os, storepwd.toCharArray());
            System.out.println("Keystore " + filename + " generated successfully.");
            System.out.println(
                "Please put keystore in correct location, restart application server and run 'ca init'.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
