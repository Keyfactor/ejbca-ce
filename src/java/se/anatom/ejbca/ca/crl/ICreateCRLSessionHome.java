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
 
package se.anatom.ejbca.ca.crl;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Home interface for Create CRL session.
 *
 * @version $Id: ICreateCRLSessionHome.java,v 1.2 2004-04-16 07:39:00 anatom Exp $
 */
public interface ICreateCRLSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IICreateCRLSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ICreateCRLSessionRemote create() throws CreateException, RemoteException;
}
