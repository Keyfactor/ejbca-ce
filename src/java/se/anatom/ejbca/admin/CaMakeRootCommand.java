
package se.anatom.ejbca.admin;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.util.KeyTools;
import se.anatom.ejbca.util.CertTools;


/** makeroot CA admin command, generates keys and creates a keystore (PKCS12) to be used by the CA
 *
 * @version $Id: CaMakeRootCommand.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public class CaMakeRootCommand extends BaseCaAdminCommand {

    /** Private key alias in PKCS12 keystores */
    private static String privKeyAlias = "privateKey";
    private static char[] privateKeyPass = null;
    
    /** Creates a new instance of CaMakeRootCommand */
    public CaMakeRootCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
                // Generates keys and creates a keystore (PKCS12) to be used by the CA
                if (args.length < 6) {
                    throw new IllegalAdminCommandException("Usage: CA makeroot <DN> <keysize> <validity-days> <filename> <storepassword>");
                } 
                String dn = args[1];
                int keysize = Integer.parseInt(args[2]);
                int validity = Integer.parseInt(args[3]);
                String filename = args[4];
                String storepwd = args[5];

                System.out.println("Generating rootCA keystore:");
                System.out.println("DN: "+dn);
                System.out.println("Keysize: "+keysize);
                System.out.println("Validity (days): "+validity);
                System.out.println("Storing in: "+filename);
                System.out.println("Protected with storepassword: "+storepwd);

                try {
                    // Generate keys
                    System.out.println("Generating keys, please wait...");
                    KeyPair rsaKeys = KeyTools.genKeys(keysize);
                    X509Certificate rootcert = CertTools.genSelfCert(dn, validity, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);
                    KeyStore ks = KeyTools.createP12(privKeyAlias, rsaKeys.getPrivate(), rootcert, (X509Certificate)null);
                    
                    FileOutputStream os = new FileOutputStream(filename);
                    System.out.println("Storing keystore '"+filename+"'.");
                    ks.store(os, storepwd.toCharArray());
                } catch (Exception e) {
                    throw new ErrorAdminCommandException(e);
                }
                System.out.println("Keystore "+filename+" generated succefully.");
    } // exceute
    
} //CaMakeRootCommand
