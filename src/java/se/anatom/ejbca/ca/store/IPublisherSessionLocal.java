
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import se.anatom.ejbca.log.Admin;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IPublicherSession for docs.
 *
 * @version $Id: IPublisherSessionLocal.java,v 1.5 2002-11-17 14:01:21 herrvendil Exp $
 * @see se.anatom.ejbca.ca.store.IPublisherSession
 */
public interface IPublisherSessionLocal extends javax.ejb.EJBLocalObject {

    /**
    * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type);
    /**
     * @see se.anatom.ejbca.ca.store.IPublisherSessionRemote
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number);

}
