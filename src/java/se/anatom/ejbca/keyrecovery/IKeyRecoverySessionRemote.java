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

import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.log.Admin;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionRemote.java,v 1.6 2004-06-08 18:06:04 sbailliez Exp $
 */
public interface IKeyRecoverySessionRemote extends javax.ejb.EJBObject {
    /**
     * Adds a certificates keyrecovery data to the database.
     *
     * @return false if the certificates keyrecovery data already exists.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean addKeyRecoveryData(Admin admin, X509Certificate certificate, String username,
                                      KeyPair keypair) throws RemoteException;

    /**
     * Updates keyrecovery data
     *
     * @return false if certificates keyrecovery data doesn't exists
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean changeKeyRecoveryData(Admin admin, X509Certificate certificate,
                                         boolean markedasrecoverable, KeyPair keypair) throws RemoteException;

    /**
     * Removes a certificates keyrecovery data from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeKeyRecoveryData(Admin admin, X509Certificate certificate)
            throws RemoteException;

    /**
     * Removes a all keyrecovery data saved for a user from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeAllKeyRecoveryData(Admin admin, String username)
            throws RemoteException;

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates key can be recovered
     * for every user at the time.
     *
     * @return the marked keyrecovery data  or null if no recoverydata can be found.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public KeyRecoveryData keyRecovery(Admin admin, String username)
            throws RemoteException;

    /**
     * Marks a users newest certificate for key recovery. Newest means certificate with latest not
     * before date.
     *
     * @return true if operation went successful or false if no certificates could be found for
     *         user.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean markNewestAsRecoverable(Admin admin, String username)
            throws RemoteException;

    /**
     * Marks a users certificate for key recovery.
     *
     * @return true if operation went successful or false if  certificate couldn't be found.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean markAsRecoverable(Admin admin, X509Certificate certificate)
            throws RemoteException;

    /**
     * Resets keyrecovery mark for a user,
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void unmarkUser(Admin admin, String username)
            throws RemoteException;

    /**
     * Returns true if a user is marked for key recovery.
     *
     * @return true if user is already marked for key recovery.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean isUserMarked(Admin admin, String username)
            throws RemoteException;

    /**
     * Returns true if specified certificates keys exists in database.
     *
     * @return true if user is already marked for key recovery.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean existsKeys(Admin admin, X509Certificate certificate)
            throws RemoteException;

}
