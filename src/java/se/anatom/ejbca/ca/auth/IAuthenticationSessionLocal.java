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
 
package se.anatom.ejbca.ca.auth;

import javax.ejb.ObjectNotFoundException;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.log.Admin;


/**
 * Interface used for authenticating entities when issuing their certificates. Local interface for
 * EJB, unforturnately this must be a copy of the remote interface except that RemoteException is
 * not thrown.
 *
 * @version $Id: IAuthenticationSessionLocal.java,v 1.8 2004-04-16 07:39:00 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
 */
public interface IAuthenticationSessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
     */
    public UserAuthData authenticateUser(Admin administrator, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException;

    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
     */
    public void finishUser(Admin administrator, String username, String password)
        throws ObjectNotFoundException;
}
