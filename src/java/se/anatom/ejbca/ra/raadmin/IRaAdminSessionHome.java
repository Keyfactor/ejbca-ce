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
 
package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IRaAdminSessionHome.java,v 1.7 2004-04-16 07:38:41 anatom Exp $
 */
public interface IRaAdminSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IRaAdminSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IRaAdminSessionRemote create() throws CreateException, RemoteException;
}
