
package se.anatom.ejbca.admin;

import java.io.*;

import javax.naming.Context;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;

/** Retrieves the latest CRL from the CA.
 *
 * @version $Id: CaGetCrlCommand.java,v 1.4 2002-09-12 18:14:15 herrvendil Exp $
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaGetCrlCommand */
    public CaGetCrlCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: CA getcrl <outfile>");
                return;
            }
            String outfile = args[1];
            Context context = getInitialContext();
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote store = storehome.create(administrator);
            byte[] crl = store.getLastCRL();
            FileOutputStream fos = new FileOutputStream(outfile);
            fos.write(crl);
            fos.close();
            System.out.println("Wrote latest CRL to " + outfile+ ".");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

}
