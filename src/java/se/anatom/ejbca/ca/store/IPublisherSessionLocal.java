
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IPublicherSession for docs.
 *
 * @version $Id: IPublisherSessionLocal.java,v 1.3 2002-06-28 06:58:16 anatom Exp $
 * @see se.anatom.ejbca.ca.store.IPublisherSession
 */
public interface IPublisherSessionLocal extends javax.ejb.EJBLocalObject {

    /**
    * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCertificate(Certificate incert, String cafp, int status, int type);
    /**
     * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCRL(byte[] incrl, String cafp, int number);

}
