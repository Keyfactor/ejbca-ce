
package se.anatom.ejbca.admin;

import java.io.*;
import javax.naming.Context;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.Base64;

/** Receive certification request and create certificate to send back.
 *
 * @version $Id: CaProcessReqCommand.java,v 1.4 2002-09-12 18:14:15 herrvendil Exp $
 */
public class CaProcessReqCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaProcessReqCommand */
    public CaProcessReqCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 5) {
                System.out.println("Usage: CA processreq <username> <password> <request-file> <outfile>");
                System.out.println("Used to receive certificate requests from subCAs and generate certificates to be sent back.");
                return;
            }
            String username = args[1];
            String password = args[2];
            String reqfile = args[3];
            String outfile = args[4];

            System.out.println("Processing cert request:");
            System.out.println("Username: "+username);
            System.out.println("Password: "+password);
            System.out.println("Request file: "+reqfile);
            byte[] b64Encoded = FileTools.readFiletoBuffer(reqfile);
            byte[] buffer;
            try {
                String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
                String endKey = "-----END CERTIFICATE REQUEST-----";
                buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
            } catch (IOException e) {
                String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
                String endKey = "-----END NEW CERTIFICATE REQUEST-----";
                buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
            }

            Context ctx = getInitialContext();
            ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
            ISignSessionRemote ss = home.create(administrator);
            X509Certificate cert = (X509Certificate) ss.createCertificate(username, password, buffer);
            FileOutputStream fos = new FileOutputStream(outfile);
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(Base64.encode(cert.getEncoded()));
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
            fos.close();
            System.out.println("Wrote certificate (PEM-format) to file " + outfile);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

}
