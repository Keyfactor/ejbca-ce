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

import javax.ejb.CreateException;

/**
 * @version $Id: IHardTokenBatchJobSessionLocalHome.java,v 1.4 2004-04-16 07:38:56 anatom Exp $
 */

public interface IHardTokenBatchJobSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenBatchJobSessionLocal interface
     */

    IHardTokenBatchJobSessionLocal create() throws CreateException;

}

