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

package org.ejbca.core.ejb.hardtoken;

import javax.ejb.Remote;

/**
 * Remote interface for HardTokenBatchJobSession.
 */
@Remote
public interface HardTokenBatchJobSessionRemote {
    /**
     * Returns the next user scheduled for batch generation for the given
     * issuer.
     * 
     * @param admin
     *            the administrator performing the actions
     * @return The next user to generate or NULL if there are no users i queue.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.ra.UserDataVO getNextHardTokenToGenerate(org.ejbca.core.model.log.Admin admin, java.lang.String alias)
            throws org.ejbca.core.model.hardtoken.UnavailableTokenException, java.rmi.RemoteException;

    /**
     * Returns a Collection of users scheduled for batch generation for the
     * given issuer. A maximum of MAX_RETURNED_QUEUE_SIZE users will be returned
     * by call.
     * 
     * @param admin
     *            the administrator performing the actions
     * @return A Collection of users to generate or NULL if there are no users i
     *         queue.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.util.Collection getNextHardTokensToGenerate(org.ejbca.core.model.log.Admin admin, java.lang.String alias)
            throws org.ejbca.core.model.hardtoken.UnavailableTokenException, java.rmi.RemoteException;

    /**
     * Returns the indexed user in queue scheduled for batch generation for the
     * given issuer.
     * 
     * @param admin
     *            the administrator performing the actions
     * @param index
     *            index in queue of user to retrieve.
     * @return The next token to generate or NULL if the given user doesn't
     *         exist in queue.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public org.ejbca.core.model.ra.UserDataVO getNextHardTokenToGenerateInQueue(org.ejbca.core.model.log.Admin admin, java.lang.String alias, int index)
            throws org.ejbca.core.model.hardtoken.UnavailableTokenException, java.rmi.RemoteException;

    /**
     * Returns the number of users scheduled for batch generation for the given
     * issuer.
     * 
     * @param admin
     *            the administrator performing the actions
     * @return the number of users to generate.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public int getNumberOfHardTokensToGenerate(org.ejbca.core.model.log.Admin admin, java.lang.String alias) throws java.rmi.RemoteException;

    /**
     * Methods that checks if a user exists in the database having the given
     * hard token issuer id. This function is mainly for avoiding
     * desyncronisation when a hard token issuer is deleted.
     * 
     * @param hardtokenissuerid
     *            the id of hard token issuer to look for.
     * @return true if hardtokenissuerid exists in userdatabase.
     */
    public boolean checkForHardTokenIssuerId(org.ejbca.core.model.log.Admin admin, int hardtokenissuerid) throws java.rmi.RemoteException;

}
