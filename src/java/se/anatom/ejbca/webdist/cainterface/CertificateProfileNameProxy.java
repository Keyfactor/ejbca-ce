package se.anatom.ejbca.webdist.cainterface;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;

import java.rmi.RemoteException;

import java.util.HashMap;

import javax.naming.*;


/**
 * A class used to improve performance by proxying certificateprofile id to certificate name
 * mappings by minimizing the number of needed lockups over rmi.
 *
 * @version $Id: CertificateProfileNameProxy.java,v 1.4 2003-06-26 11:43:25 anatom Exp $
 */
public class CertificateProfileNameProxy {
    /**
     * Creates a new instance of ProfileNameProxy
     *
     * @param administrator administrator using this class
     */
    public CertificateProfileNameProxy(Admin administrator)
        throws Exception {
        // Get the RaAdminSession instance.
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome certificatestoresessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                    "CertificateStoreSession"), ICertificateStoreSessionHome.class);
        certificatestoresession = certificatestoresessionhome.create();

        certificateprofilenamestore = new HashMap();
        this.admin = administrator;
    }

    /**
     * Method that first tries to find certificateprofile name in local hashmap and if it doesn't
     * exists looks it up over RMI.
     *
     * @param certificateprofileid the certificateprofile id number to look up.
     *
     * @return the certificateprofilename or null if no certificateprofilename is relatied to the
     *         given id
     */
    public String getCertificateProfileName(int certificateprofileid)
        throws RemoteException {
        String returnval = null;

        // Check if name is in hashmap
        returnval = (String) certificateprofilenamestore.get(new Integer(certificateprofileid));

        if (returnval == null) {
            // Retreive profilename over RMI
            returnval = certificatestoresession.getCertificateProfileName(admin,
                    certificateprofileid);

            if (returnval != null) {
                certificateprofilenamestore.put(new Integer(certificateprofileid), returnval);
            }
        }

        return returnval;
    }

    // Private fields
    private HashMap certificateprofilenamestore;
    private ICertificateStoreSessionRemote certificatestoresession;
    private Admin admin;
}
