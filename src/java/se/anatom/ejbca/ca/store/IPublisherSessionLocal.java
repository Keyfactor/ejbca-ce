package se.anatom.ejbca.ca.store;

import java.security.cert.Certificate;

import se.anatom.ejbca.log.Admin;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IPublicherSession for docs.
 *
 * @version $Id: IPublisherSessionLocal.java,v 1.11 2003-07-24 08:43:30 anatom Exp $
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
