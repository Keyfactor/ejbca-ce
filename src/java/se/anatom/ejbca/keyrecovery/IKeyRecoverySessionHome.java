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
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionHome.java,v 1.4 2004-06-08 18:06:04 sbailliez Exp $
 */
public interface IKeyRecoverySessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IKeyRecoverySessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IKeyRecoverySessionRemote create() throws CreateException, RemoteException;
}
