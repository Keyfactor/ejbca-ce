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
 
package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;



/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataHome.java,v 1.12 2004-04-16 07:38:56 anatom Exp $
 **/

public interface UserDataHome extends javax.ejb.EJBHome {

    public UserDataRemote create(String username, String password, String dn, int caid)
        throws CreateException, NoSuchAlgorithmException, RemoteException;


    public UserDataRemote findByPrimaryKey(UserDataPK pk)
        throws FinderException, RemoteException;

    public UserDataRemote findBySubjectDN(String dn, int caid)          
        throws FinderException, RemoteException;
    
     public Collection findBySubjectEmail(String email)          
        throws FinderException, RemoteException;   
    
    /** Finds users with a specified status.
     * @param status the status of the required users
     * @return Collection of UserDataRemote in no specific order
     */

    public Collection findByStatus(int status)
        throws FinderException, RemoteException;
    
    public Collection findAll() 
        throws FinderException, RemoteException;    
}

