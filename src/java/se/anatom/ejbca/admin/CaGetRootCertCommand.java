package se.anatom.ejbca.admin;

import java.io.*;

import java.util.ArrayList;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


/**
 * Export root CA certificate.
 *
 * @version $Id: CaGetRootCertCommand.java,v 1.5 2003-09-03 14:32:02 herrvendil Exp $
 */
public class CaGetRootCertCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaGetRootCertCommand
     *
     * @param args command line arguments
     */
    public CaGetRootCertCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 3) {
            String msg = "Save root CA certificate (DER-format) to file.\n";
            msg += "Usage: CA rootcert <caname> <filename>";
            throw new IllegalAdminCommandException(msg);
        }

        String caname = args[1];
        String filename = args[2];
        
        try {
            ArrayList chain = new ArrayList(getCertChain(caname));
            X509Certificate rootcert = (X509Certificate)chain.get(chain.size()-1);

            FileOutputStream fos = new FileOutputStream(filename);
            fos.write(rootcert.getEncoded());
            fos.close();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }

        System.out.println("Wrote Root CA certificate to '" + filename + "'");
    }

    // execute
}
