/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.anatom.ejbca.keyrecovery;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.log.Admin;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IKeyRecoverySessionRemote for docs.
 *
 * @version $Id: IKeyRecoverySessionLocal.java,v 1.7 2004-06-08 18:06:04 sbailliez Exp $
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
