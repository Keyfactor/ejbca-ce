package se.anatom.ejbca.admin;

import java.io.*;

import javax.naming.Context;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;


/**
 * Retrieves the latest CRL from the CA.
 *
 * @version $Id: CaGetCrlCommand.java,v 1.10 2003-10-03 14:34:20 herrvendil Exp $
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaGetCrlCommand
     *
     * @param args command line arguments
     */
    public CaGetCrlCommand(String[] args) {
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
				throw new IllegalAdminCommandException("Usage: CA getcrl <caname> <outfile>");
			}
			try {
				String outfile = args[2];
                String caname = args[1];
                String issuerdn = getIssuerDN(caname);
				Context context = getInitialContext();
				ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"),ICertificateStoreSessionHome.class);
				ICertificateStoreSessionRemote store = storehome.create();
				byte[] crl = store.getLastCRL(administrator, issuerdn);
				FileOutputStream fos = new FileOutputStream(outfile);
				fos.write(crl);
				fos.close();
				System.out.println("Wrote latest CRL to " + outfile + ".");
			} catch (Exception e) {
				throw new ErrorAdminCommandException(e);
			}
    } // execute

}
