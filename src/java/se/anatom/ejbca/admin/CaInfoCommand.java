package se.anatom.ejbca.admin;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Iterator;

import se.anatom.ejbca.util.CertTools;


/**
 * Gets and prints info about the CA.
 *
 * @version $Id: CaInfoCommand.java,v 1.6 2003-09-03 14:32:02 herrvendil Exp $
 */
public class CaInfoCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaInfoCommand
     *
     * @param args command line arguments
     */
    public CaInfoCommand(String[] args) {
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
            
            // Create new CA.
            if (args.length < 2) {
               String msg = "Usage: CA info <caname>";               
               throw new IllegalAdminCommandException(msg);
            }
            
            String caname = args[1];
            
            ArrayList chain = new ArrayList(getCertChain(caname));
            
            if (chain.size() < 2)
              System.out.println("This is a Root CA.");
            else
              System.out.println("This is a subordinate CA.");
              
              System.out.println("Size of chain :" + chain.size());
            
            X509Certificate rootcert = (X509Certificate)chain.get(chain.size()-1);
            System.out.println("Root CA DN: "+CertTools.getSubjectDN(rootcert));
            System.out.println("Certificate valid from: "+rootcert.getNotBefore().toString());
            System.out.println("Certificate valid to: "+rootcert.getNotAfter().toString());
            System.out.println("Root CA keysize: "+((RSAPublicKey)rootcert.getPublicKey()).getModulus().bitLength());            
            for(int i = chain.size()-2; i>=0; i--){                                          
                X509Certificate cacert = (X509Certificate)chain.get(i);
                System.out.println("CA DN: "+CertTools.getSubjectDN(cacert));
                System.out.println("Certificate valid from: "+cacert.getNotBefore().toString());
                System.out.println("Certificate valid to: "+cacert.getNotAfter().toString());
                System.out.println("CA keysize: "+((RSAPublicKey)cacert.getPublicKey()).getModulus().bitLength());

            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
