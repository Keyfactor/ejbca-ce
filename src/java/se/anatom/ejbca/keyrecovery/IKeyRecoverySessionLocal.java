package se.anatom.ejbca.keyrecovery;

import se.anatom.ejbca.log.Admin;

import java.security.KeyPair;
import java.security.cert.X509Certificate;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IKeyRecoverySessionRemote for docs.
 *
 * @version $Id: IKeyRecoverySessionLocal.java,v 1.4 2003-06-26 11:43:24 anatom Exp $
 *
 * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
 */
public interface IKeyRecoverySessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean addKeyRecoveryData(Admin admin, X509Certificate certificate, String username,
        KeyPair keypair);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean changeKeyRecoveryData(Admin admin, X509Certificate certificate,
        boolean markedasrecoverable, KeyPair keypair);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public void removeKeyRecoveryData(Admin admin, X509Certificate certificate);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public void removeAllKeyRecoveryData(Admin admin, String username);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public KeyRecoveryData keyRecovery(Admin admin, String username);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean markNewestAsRecoverable(Admin admin, String username);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean markAsRecoverable(Admin admin, X509Certificate certificate);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public void unmarkUser(Admin admin, String username);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean isUserMarked(Admin admin, String username);

    /**
     * @see java.se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote
     */
    public boolean existsKeys(Admin admin, X509Certificate certificate);
}
