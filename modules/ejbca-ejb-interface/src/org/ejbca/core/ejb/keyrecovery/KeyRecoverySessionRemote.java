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
package org.ejbca.core.ejb.keyrecovery;

import javax.ejb.Remote;

/**
 * Remote interface for KeyRecoverySession.
 */
@Remote
public interface KeyRecoverySessionRemote {
    /**
     * Adds a certificates keyrecovery data to the database.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate used with the keypair.
     * @param username
     *            of the administrator
     * @param keypair
     *            the actual keypair to save.
     * @return false if the certificates keyrecovery data already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean addKeyRecoveryData(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate certificate, java.lang.String username,
            java.security.KeyPair keypair) throws java.rmi.RemoteException;

    /**
     * Updates keyrecovery data
     * 
     * @param admin
     *            DOCUMENT ME!
     * @param certificate
     *            DOCUMENT ME!
     * @param markedasrecoverable
     *            DOCUMENT ME!
     * @param keypair
     *            DOCUMENT ME!
     * @return false if certificates keyrecovery data doesn't exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean changeKeyRecoveryData(org.ejbca.core.model.log.Admin admin, java.security.cert.X509Certificate certificate, boolean markedasrecoverable,
            java.security.KeyPair keypair) throws java.rmi.RemoteException;

    /**
     * Removes a certificates keyrecovery data from the database.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate used with the keys about to be removed.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeKeyRecoveryData(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate certificate) throws java.rmi.RemoteException;

    /**
     * Removes a all keyrecovery data saved for a user from the database.
     * 
     * @param admin
     *            DOCUMENT ME!
     * @param username
     *            DOCUMENT ME!
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void removeAllKeyRecoveryData(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates
     * key can be recovered for every user at the time.
     * 
     * @param admin
     * @param username
     * @param endentityprofileid
     *            , the end entity profile id the user belongs to.
     * @return the marked keyrecovery data or null if no recoverydata can be
     *         found.
     * @throws AuthorizationDeniedException
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.keyrecovery.KeyRecoveryData keyRecovery(org.ejbca.core.model.log.Admin admin, java.lang.String username, int endEntityProfileId)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, java.rmi.RemoteException;

    /**
     * Marks a users newest certificate for key recovery. Newest means
     * certificate with latest not before date.
     * 
     * @param admin
     *            the administrator calling the function
     * @param username
     *            or the user.
     * @param the
     *            end entity profile of the user, used for access control
     * @param gc
     *            The GlobalConfiguration used to extract approval information
     * @return true if operation went successful or false if no certificates
     *         could be found for user, or user already marked.
     * @throws AuthorizationDeniedException
     * @throws WaitingForApprovalException
     * @throws ApprovalException
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean markNewestAsRecoverable(org.ejbca.core.model.log.Admin admin, java.lang.String username, int endEntityProfileId,
            org.ejbca.core.model.ra.raadmin.GlobalConfiguration gc) throws org.ejbca.core.model.authorization.AuthorizationDeniedException,
            org.ejbca.core.model.approval.ApprovalException, org.ejbca.core.model.approval.WaitingForApprovalException, java.rmi.RemoteException;

    /**
     * Marks a users certificate for key recovery.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate used with the keys about to be removed.
     * @param gc
     *            The GlobalConfiguration used to extract approval information
     * @return true if operation went successful or false if certificate
     *         couldn't be found.
     * @throws AuthorizationDeniedException
     * @throws WaitingForApprovalException
     * @throws ApprovalException
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean markAsRecoverable(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate certificate, int endEntityProfileId,
            org.ejbca.core.model.ra.raadmin.GlobalConfiguration gc) throws org.ejbca.core.model.authorization.AuthorizationDeniedException,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.approval.ApprovalException, java.rmi.RemoteException;

    /**
     * Resets keyrecovery mark for a user,
     * 
     * @param admin
     *            DOCUMENT ME!
     * @param username
     *            DOCUMENT ME!
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void unmarkUser(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * Returns true if a user is marked for key recovery.
     * 
     * @param admin
     *            DOCUMENT ME!
     * @param username
     *            DOCUMENT ME!
     * @return true if user is already marked for key recovery.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean isUserMarked(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;

    /**
     * Returns true if specified certificates keys exists in database.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate used with the keys about to be removed.
     * @return true if user is already marked for key recovery.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean existsKeys(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate certificate) throws java.rmi.RemoteException;
}
