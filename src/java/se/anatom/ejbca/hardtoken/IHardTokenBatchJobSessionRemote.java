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
 
package se.anatom.ejbca.hardtoken;
import java.rmi.RemoteException;
import java.util.Collection;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.UserAdminData;

/**
 * Remote interface for bean used by hardtoken batchprograms to retrieve users to generate from RA. 
 *
 * @version $Id: IHardTokenBatchJobSessionRemote.java,v 1.6 2004-04-16 07:38:56 anatom Exp $
 */
public interface IHardTokenBatchJobSessionRemote extends javax.ejb.EJBObject {
    
    public static final int MAX_RETURNED_QUEUE_SIZE = 300;
    
    /**
     * Returns the next user scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param alias the alias of the hard token issuer.
     *
     * @return The next user to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public UserAdminData getNextHardTokenToGenerate(Admin admin, String alias)  throws UnavailableTokenException, RemoteException;

    /**
     * Returns a Collection of users scheduled for batch generation for the given issuer. 
     * A maximum of MAX_RETURNED_QUEUE_SIZE users will be returned by call.
     *
     * @param admin the administrator performing the actions
     * @param alias the alias of the hard token issuer.
     *
     * @return A Collection of users to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
       
    public Collection getNextHardTokensToGenerate(Admin admin, String alias)  throws UnavailableTokenException, RemoteException;
    
    /**
     * Returns the indexed user in queue scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param alias the alias of the hard token issuer.
     * @param index index in queue of user to retrieve.
     *
     * @return The next token to generate or NULL if there are no users i queue.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public UserAdminData getNextHardTokenToGenerateInQueue(Admin admin, String alias, int index)  throws UnavailableTokenException, RemoteException;
    
     /**
     * Returns the number of users scheduled for batch generation for the given issuer.
     *
     * @param admin the administrator performing the actions
     * @param alias the alias of the hard token issuer.
     *
     * @return the number of users to generate.
     * @throws EJBException if a communication or other error occurs.
     */ 
    
       
    public int getNumberOfHardTokensToGenerate(Admin admin, String alias) throws RemoteException;    
    
    /**
     * Methods that checks if a user exists in the database having the given hard token issuer id. This function is mainly for avoiding
     * desyncronisation when a hard token issuer is deleted.
     *
     * @param hardtokenissuerid the id of hard token issuer to look for.
     * @return true if hardtokenissuerid exists in userdatabase.
     */
    public boolean checkForHardTokenIssuerId(Admin admin, int hardtokenissuerid) throws RemoteException;  

}

