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

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionLocalHome.java,v 1.5 2004-06-08 18:06:04 sbailliez Exp $
 */
public interface IKeyRecoverySessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenSessionLocal interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IKeyRecoverySessionLocal create() throws CreateException;
}
