package se.anatom.ejbca.admin;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import se.anatom.ejbca.util.CertTools;


/**
 * Gets and prints info about the CA.
 *
 * @version $Id: CaInfoCommand.java,v 1.5 2003-07-24 08:43:29 anatom Exp $
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
            Certificate[] chain = getCertChain();

            if (chain.length < 2) {
                System.out.println("This is a Root CA.");
            } else {
                System.out.println("This is a subordinate CA.");
            }

            X509Certificate rootcert = (X509Certificate) chain[chain.length - 1];
            System.out.println("Root CA DN: " + CertTools.getSubjectDN(rootcert));
            System.out.println("Certificate valid from: " + rootcert.getNotBefore().toString());
            System.out.println("Certificate valid to: " + rootcert.getNotAfter().toString());
            System.out.println("Root CA keysize: " +
                ((RSAPublicKey) rootcert.getPublicKey()).getModulus().bitLength());

            if (chain.length > 1) {
                X509Certificate cacert = (X509Certificate) chain[chain.length - 2];
                System.out.println("CA DN: " + CertTools.getSubjectDN(cacert));
                System.out.println("Certificate valid from: " + cacert.getNotBefore().toString());
                System.out.println("Certificate valid to: " + cacert.getNotAfter().toString());
                System.out.println("CA keysize: " +
                    ((RSAPublicKey) cacert.getPublicKey()).getModulus().bitLength());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
