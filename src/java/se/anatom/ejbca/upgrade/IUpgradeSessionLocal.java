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
 
package se.anatom.ejbca.upgrade;

import se.anatom.ejbca.log.Admin;

/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IUpgradeSessionRemote for docs.
 *
 * @version $Id: IUpgradeSessionLocal.java,v 1.2 2004-04-16 07:39:02 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.store.IUpgradeSessionRemote
 */
public interface IUpgradeSessionLocal extends javax.ejb.EJBLocalObject {
	
    /** Upgrades the database
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     * @throws RemoteException
     */
    public boolean upgrade(Admin admin);	

}
