
package se.anatom.ejbca.admin;

import java.io.*;
import java.util.Vector;
import javax.naming.Context;
import java.rmi.RemoteException;
import javax.naming.NamingException;
import javax.ejb.CreateException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.store.IPublisherSessionRemote;
import se.anatom.ejbca.ca.store.IPublisherSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;

/** Inits the CA by creating the first CRL and publiching the CRL and CA certificate.
 *
 * @version $Id: CaInitCommand.java,v 1.3 2002-06-04 14:42:04 anatom Exp $
 */
public class CaInitCommand extends BaseCaAdminCommand {

    /** Pointer to main certificate store */
    private static ICertificateStoreSessionRemote certificateStore = null;
    /** A vector of publishers where certs and CRLs are stored */
    private static Vector publishers = null;

    /** Creates a new instance of CaInitCommand */
    public CaInitCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            System.out.println("Initializing CA");
            // First get and publish CA certificates
            Context context = getInitialContext();
            ISignSessionHome signhome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("RSASignSession"), ISignSessionHome.class);
            ISignSessionRemote sign = signhome.create();
            Certificate[] certs = sign.getCertificateChain();
            initCertificateStore();
            for (int j=0;j<certs.length;j++) {
                X509Certificate cert = (X509Certificate)certs[j];
                String cafingerprint = null;
                int type = SecConst.USER_CA;
                if ( (!CertTools.isSelfSigned(cert)) && ((j+1) < certs.length) )
                    cafingerprint = CertTools.getFingerprintAsString((X509Certificate)certs[j+1]);
                else {
                    cafingerprint = CertTools.getFingerprintAsString(cert);
                    type = SecConst.USER_ROOTCA;
                }
                try {
                    // We will get an exception if the entity already exist
                    certificateStore.storeCertificate(cert, cafingerprint, CertificateData.CERT_ACTIVE, type);
                } catch (java.rmi.ServerException e) {
                    System.out.println("Certificate for subject '"+cert.getSubjectDN()+"' already exist in the certificate store.");
                }
                // Call authentication session and tell that we are finished with this user
                for (int i=0;i<publishers.size();i++) {
                    ((IPublisherSessionRemote)(publishers.get(i))).storeCertificate(cert, cafingerprint, CertificateData.CERT_ACTIVE, type);
                }
                System.out.println("-Stored CA certificates in certificate store(s).");
            }
            // Second create (and publish) CRL
            createCRL();
            System.out.println("-Created and published initial CRL.");
            System.out.println("CA initialized");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

    /**
     * Creates the CertificateStore and Publishers so they are available.
     */
    private void initCertificateStore() throws RemoteException {
        debug(">initCertificateStore()");
        Context context = null;
        try {
            context = getInitialContext();
            // First init main certificate store
            if (certificateStore == null) {
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
                certificateStore = storehome.create();
            }
        } catch (NamingException e) {
            // We could not find this publisher
            error("Failed to find cert store.");
            e.printStackTrace();
        } catch (CreateException ce) {
            // We could not find this publisher
            error("Failed to create cert store.");
            ce.printStackTrace();
        }
        // Init the publisher session beans
        if (publishers == null) {
            int i = 1;
            publishers = new Vector(0);
            try {
                while (true) {
                    String jndiName = "PublisherSession" + i;
                    IPublisherSessionHome pubhome = (IPublisherSessionHome)javax.rmi.PortableRemoteObject.narrow(context.lookup(jndiName), IPublisherSessionHome.class);
                    IPublisherSessionRemote pub = pubhome.create();
                    publishers.add(pub);
                    debug("Added publisher class '"+pub.getClass().getName()+"'");
                    i++;
                }

            } catch (NamingException e) {
                // We could not find this publisherm this is not an error
                debug("Failed to find publisher at index '"+i+"', no more publishers.");
            } catch (CreateException ce) {
                // We could not find this publisher
                error("Failed to create configured publisher.");
                ce.printStackTrace();
            }
        }
        debug("<initCertificateStore()");
    } // initCertificateStore

}
