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
 
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.6 2004-04-16 07:38:58 anatom Exp $
 */
public interface ICertificateStoreSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICertificateStoreSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ICertificateStoreSessionLocal create() throws CreateException;
}
