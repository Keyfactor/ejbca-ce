package se.anatom.ejbca.admin;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;


/**
 * makeroot CA admin command, generates keys and creates a keystore (PKCS12) to be used by the CA
 *
 * @version $Id: CaMakeRootCommand.java,v 1.9 2003-10-04 10:12:40 anatom Exp $
 */
public class CaMakeRootCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaMakeRootCommand
     *
     * @param args command line arguments
     */
    public CaMakeRootCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        // Generates keys and creates a keystore (PKCS12) to be used by the CA
        if (args.length < 7) {
            String msg = "Usage: CA makeroot <DN> <keysize> <validity-days> <policyID> <filename> <storepassword>";
            msg += "\npolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0'.";
            throw new IllegalAdminCommandException(msg);
        }
        String dn = args[1];
        int keysize = Integer.parseInt(args[2]);
        int validity = Integer.parseInt(args[3]);
        String policyId = args[4];
        String filename = args[5];
        String storepwd = args[6];
        if (policyId.equals("null"))
            policyId = null;

        System.out.println("Generating rootCA keystore:");
        System.out.println("DN: "+dn);
        System.out.println("Keysize: "+keysize);
        System.out.println("Validity (days): "+validity);
        System.out.println("Policy ID: "+policyId);
        System.out.println("Storing in: "+filename);
        System.out.println("Protected with storepassword: "+storepwd);

        try {
            // Generate keys
            System.out.println("Generating keys, please wait...");
            KeyPair rsaKeys = KeyTools.genKeys(keysize);
            X509Certificate rootcert = CertTools.genSelfCert("CN=dummy", 36500, null, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);
            //X509Certificate rootcert = CertTools.genSelfCert(dn, validity, policyId, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);
            KeyStore ks = KeyTools.createP12(privKeyAlias, rsaKeys.getPrivate(), rootcert, (X509Certificate)null);

            FileOutputStream os = new FileOutputStream(filename);
            System.out.println("Storing keystore '"+filename+"'.");
            ks.store(os, storepwd.toCharArray());
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
        System.out.println("Keystore "+filename+" generated successfully.");         
    } // exceute

}//CaMakeRootCommand
