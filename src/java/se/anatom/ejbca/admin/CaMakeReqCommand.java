
package se.anatom.ejbca.admin;

import java.io.*;

import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyStore;

import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

/** Generates keys and creates a keystore (PKCS12) to be used by the CA.
 *
 * @version $Id: CaMakeReqCommand.java,v 1.1 2002-04-13 18:11:27 anatom Exp $
 */
public class CaMakeReqCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaMakeReqCommand */
    public CaMakeReqCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 7) {
                System.out.println("Usage: CA makereq <DN> <keysize> <rootca-certificate> <request-file> <keystore-file> <storepassword>");
                System.out.println("Generates a certification request for a subCA for sending to a RootCA.");
                return;
            }
            String dn = args[1];
            int keysize = Integer.parseInt(args[2]);
            String rootfile = args[3];
            String reqfile = args[4];
            String ksfile = args[5];
            String storepwd = args[6];
            
            System.out.println("Generating cert request (and keystore):");
            System.out.println("DN: "+dn);
            System.out.println("Keysize: "+keysize);
            System.out.println("RootCA cert file: "+rootfile);
            System.out.println("Storing CertificationRequest in: "+reqfile);
            System.out.println("Storing KeyStore in: "+ksfile);
            System.out.println("Protected with storepassword: "+storepwd);
            
            // Read in RootCA certificate
            X509Certificate rootcert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(rootfile));
            
            // Generate keys
            System.out.println("Generating keys, please wait...");
            KeyPair rsaKeys = KeyTools.genKeys(keysize);
            // Create selfsigned cert...
            X509Certificate selfcert = CertTools.genSelfCert(dn, 365, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);
            
            // Create certificate request
            makeCertRequest(dn, rsaKeys, reqfile);
            
            // Create keyStore
            KeyStore ks = KeyTools.createP12("privateKey", rsaKeys.getPrivate(), selfcert, rootcert);
            
            FileOutputStream os = new FileOutputStream(ksfile);
            ks.store(os, storepwd.toCharArray());
            System.out.println("Keystore '"+ksfile+"' generated succefully.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
