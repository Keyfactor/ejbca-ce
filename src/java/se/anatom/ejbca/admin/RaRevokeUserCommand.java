
package se.anatom.ejbca.admin;

import java.io.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserData;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSession;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Hex;

/** Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id: RaRevokeUserCommand.java,v 1.2 2002-05-20 17:52:59 anatom Exp $
 */
public class RaRevokeUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaRevokeUserCommand */
    public RaRevokeUserCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                System.out.println("Usage: RA revokeuser <username>");
                return;
            }
            String username = args[1];
            UserAdminData data = getAdminSession().findUser(username);
            System.out.println("Found user:");
            System.out.println("username="+data.getUsername());
            System.out.println("dn=\""+data.getDN()+"\"");
            System.out.println("Old status="+data.getStatus());
            getAdminSession().setUserStatus(username, UserData.STATUS_REVOKED);
            System.out.println("New status="+UserData.STATUS_REVOKED);
            
            Object obj2 = getInitialContext().lookup("CertificateStoreSession");
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
            ICertificateStoreSession store = storehome.create();
            Certificate[] certs = store.findCertificatesBySubject(data.getDN());
            // Revoke all certs
            if (certs.length > 0 ) {
                Object obj = getInitialContext().lookup("CertificateData");
                CertificateDataHome home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj, CertificateDataHome.class);
                for (int i=0; i<certs.length;i++) {
                    CertificateDataPK revpk = new CertificateDataPK();
                    revpk.fingerprint = CertTools.getFingerprintAsString((X509Certificate)certs[i]);
                    CertificateData rev = home.findByPrimaryKey(revpk);
                    if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                        rev.setStatus(CertificateData.CERT_REVOKED);
                        rev.setRevocationDate(new Date());
                        System.out.println("Revoked cert with serialNumber "+Hex.encode(((X509Certificate)certs[i]).getSerialNumber().toByteArray()));
                    }
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
