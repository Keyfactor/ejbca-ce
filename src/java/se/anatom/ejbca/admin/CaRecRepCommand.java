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
 * @version $Id: CaRecRepCommand.java,v 1.9 2004-03-04 11:18:39 anatom Exp $
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
        try {
            if (args.length < 4) {
                System.out.println("Usage: CA recrep <certificate-file> <keystore-file> <storepassword>");
                System.out.println("Used to receive certificates which has been produced as result of sending a certificate request to a CA.");
                return;
            }

            String certfile = args[1];
            String ksfile = args[2];
            String storepwd = args[3];

            System.out.println("Receiving cert reply:");
            System.out.println("Cert reply file: " + certfile);
            System.out.println("Storing KeyStore in: " + ksfile);
            System.out.println("Protected with storepassword: " + storepwd);

            X509Certificate cert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(certfile));
            X509Certificate rootcert = null;
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            FileInputStream fis = new FileInputStream(ksfile);
            store.load(fis, storepwd.toCharArray());
            Certificate[] certchain = store.getCertificateChain(privKeyAlias);
            System.out.println("Loaded certificate chain with length " + certchain.length + " with alias 'privateKey'.");
            if (certchain.length == 0) {
                System.out.println("No certificate in chain with alias 'privateKey' in keystore '"+ksfile +"'");
                System.out.println("Reply NOT received!");
                return;                
            }
            if (!CertTools.isSelfSigned((X509Certificate)certchain[0])) {
                System.out.println("Certificate in chain with alias 'privateKey' in keystore '"+ksfile +"' is not selfsigned");
                System.out.println("Reply NOT received!");
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
                System.out.println("Public key in received certificate does not match private key.");
                System.out.println("Reply NOT received!");
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
            System.out.println("Keystore '" + ksfile + "' generated successfully.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    // execute
}
