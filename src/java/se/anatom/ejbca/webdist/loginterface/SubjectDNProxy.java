package se.anatom.ejbca.webdist.loginterface;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.CertTools;


/**
 * A class used to improve performance by proxying certificatesnr to subjectdn mappings by
 * minimizing the number of needed lockups over rmi.
 *
 * @version $Id: SubjectDNProxy.java,v 1.6 2003-07-24 08:43:33 anatom Exp $
 */
public class SubjectDNProxy {
    /**
     * Creates a new instance of SubjectDNProxy with remote access to CA part
     *
     * @param admin DOCUMENT ME!
     * @param certificatesession DOCUMENT ME!
     */
    public SubjectDNProxy(Admin admin, ICertificateStoreSessionRemote certificatesession) {
        // Get the RaAdminSession instance.
        this.local = false;
        this.certificatesessionremote = certificatesession;
        this.subjectdnstore = new HashMap();
        this.admin = admin;
    }

    /**
     * Creates a new instance of SubjectDNProxy with local access to CA part
     *
     * @param certificatesession DOCUMENT ME!
     */
    public SubjectDNProxy(ICertificateStoreSessionLocal certificatesession) {
        // Get the RaAdminSession instance.
        this.local = true;
        this.certificatesessionlocal = certificatesession;
        this.subjectdnstore = new HashMap();
    }

    /**
     * Method that first tries to find subjectDN in local hashmap and if it doesn't exists looks it
     * up over RMI.
     *
     * @param certificatesnr the certificate serial number number to look up.
     *
     * @return the subjectDN or null if no subjectDN is relatied to the given id
     */
    public String getSubjectDN(String certificatesnr) throws RemoteException {
        String returnval = null;
        Collection result = null;

        // Check if name is in hashmap
        returnval = (String) subjectdnstore.get(certificatesnr);

        if (returnval == null) {
            // Retreive subjectDN over RMI
            if (local) {
                result = certificatesessionlocal.findCertificatesBySerno(admin,
                        new BigInteger(certificatesnr, 16));
            } else {
                result = certificatesessionremote.findCertificatesBySerno(admin,
                        new BigInteger(certificatesnr, 16));
            }

            if (result != null) {
                Iterator i = result.iterator();

                if (i.hasNext()) {
                    returnval = CertTools.getSubjectDN((X509Certificate) i.next());
                    subjectdnstore.put(certificatesnr, returnval);
                }
            }
        }

        return returnval;
    }

    // Private fields
    private boolean local;
    private HashMap subjectdnstore;
    private ICertificateStoreSessionLocal certificatesessionlocal;
    private ICertificateStoreSessionRemote certificatesessionremote;
    private Admin admin;
}
