package se.anatom.ejbca.admin;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.KeyTools;


/**
 * Receive certificate reply as result of certificate request.
 *
 * @version $Id: CaRecRepCommand.java,v 1.7 2003-09-03 14:32:02 herrvendil Exp $
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
        System.out.println("TODO");
        //TODO
        
        /*
        try {
            if (args.length < 4) {
                System.out.println(
                    "Usage: CA recrep <certificate-file> <keystore-file> <storepassword>");
                System.out.println(
                    "Used to receive certificates which has been produced as result of sending a certificate request to a RootCA.");

                return;
            }

            String certfile = args[1];
            String ksfile = args[2];
            String storepwd = args[3];

            System.out.println("Receiving cert reply:");
            System.out.println("Cert reply file: " + certfile);
            System.out.println("Storing KeyStore in: " + ksfile);
            System.out.println("Protected with storepassword: " + storepwd);

            X509Certificate cert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(
                        certfile));
            X509Certificate rootcert = null;
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fis = new FileInputStream(ksfile);
            store.load(fis, storepwd.toCharArray());

            Certificate[] certchain = store.getCertificateChain("privateKey");
            System.out.println("Loaded certificate chain with length " + certchain.length +
                " with alias 'privateKey'.");

            if (certchain.length > 1) {
                // We have whole chain at once
                if (!CertTools.isSelfSigned((X509Certificate) certchain[1])) {
                    System.out.println(
                        "Last certificate in chain with alias 'privateKey' in keystore '" + ksfile +
                        "' is not root certificate (selfsigned)");
                    System.out.println("Reply NOT received!");

                    return;
                }

                if (certchain.length > 2) {
                    System.out.println(
                        "Certificate chain length is larger than 2, only 2 is supported.");
                    System.out.println("Reply NOT received!");

                    return;
                }

                rootcert = (X509Certificate) certchain[1];
            } else {
                String ialias = CertTools.getPartFromDN(CertTools.getIssuerDN(cert), "CN");
                Certificate[] chain1 = store.getCertificateChain(ialias);
                System.out.println("Loaded certificate chain with length " + chain1.length +
                    " with alias '" + ialias + "'.");

                if (chain1.length == 0) {
                    System.out.println("No CA-certificate found!");
                    System.out.println("Reply NOT received!");

                    return;
                }

                if (!CertTools.isSelfSigned((X509Certificate) chain1[0])) {
                    System.out.println("Certificate in chain with alias '" + ialias +
                        "' in keystore '" + ksfile + "' is not root certificate (selfsigned)");
                    System.out.println("Reply NOT received!");

                    return;
                }

                rootcert = (X509Certificate) chain1[0];
            }

            PrivateKey privKey = (PrivateKey) store.getKey("privateKey", null);

            // check if the private and public keys match
            Signature sign = Signature.getInstance("SHA1WithRSA");
            sign.initSign(privKey);
            sign.update("foooooooooooooooo".getBytes());

            byte[] signature = sign.sign();
            sign.initVerify(cert.getPublicKey());
            sign.update("foooooooooooooooo".getBytes());

            if (sign.verify(signature) == false) {
                System.out.println("Public key in received certificate does not match private key.");
                System.out.println("Reply NOT received!");

                return;
            }

            // Create new keyStore
            KeyStore ks = KeyTools.createP12("privateKey", privKey, cert, rootcert);
            FileOutputStream os = new FileOutputStream(ksfile);
            ks.store(os, storepwd.toCharArray());
            System.out.println("Keystore '" + ksfile + "' generated successfully.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
         */
    } // execute

    // execute
}
