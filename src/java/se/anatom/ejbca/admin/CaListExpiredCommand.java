
package se.anatom.ejbca.admin;

import java.io.*;
import java.util.Date;
import javax.naming.*;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSession;

/** List certificates that will expire within the given number of days.
 *
 * @version $Id: CaListExpiredCommand.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public class CaListExpiredCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaListExpiredCommand */
    public CaListExpiredCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
            String msg = "List certificates that will expire within the given number of days.\n";
            msg += "Usage: CA listexpired <days>";
            throw new IllegalAdminCommandException(msg);
        }
        String filename = args[1];
        
        try {
            long days = Long.parseLong(args[1]);
            Date findDate = new Date();
            long millis = (days * 24 * 60 * 60 * 1000);
            findDate.setTime(findDate.getTime() + (long)millis);
            System.out.println("Looking for certificates that expire before "+findDate+".");
            Certificate[] certs = getExpiredCerts(findDate);
            if (certs != null) {
                for (int i=0;i<certs.length;i++) {
                    X509Certificate xcert = (X509Certificate)certs[i];
                    Date retDate = xcert.getNotAfter();
                    String subjectDN= xcert.getSubjectDN().toString();
                    String serNo = xcert.getSerialNumber().toString();
                    System.out.println("Certificate with subjectDN '"+subjectDN+"' and serialNumber '"+serNo+"' expires at "+retDate+".");
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

    private Certificate[] getExpiredCerts(Date findDate) {
        try {
            Context ctx = getInitialContext();
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );;
            ICertificateStoreSession store = storehome.create();
            debug("Looking for cert with expireDate="+findDate);
            Certificate[] certs = store.findCertificatesByExpireTime(findDate);
            debug("Found "+certs.length+" certs.");
            return certs;
        } catch (Exception e) {
            error("Error getting list of certificates", e);
        }
        return null;
    } // getExpiredCerts
    
}
