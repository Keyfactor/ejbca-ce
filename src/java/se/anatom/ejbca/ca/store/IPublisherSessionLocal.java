package se.anatom.ejbca.ca.store;

import se.anatom.ejbca.log.Admin;

import java.security.cert.Certificate;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IPublicherSession for docs.
 *
 * @version $Id: IPublisherSessionLocal.java,v 1.10 2003-06-26 11:43:23 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
 */
public interface IPublisherSessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp,
        int status, int type);

    /**
     * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number);

    /**
     * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public void revokeCertificate(Admin admin, Certificate cert, int reason);
}
