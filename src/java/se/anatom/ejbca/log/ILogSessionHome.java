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

package se.anatom.ejbca.log;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionHome.java,v 1.7 2004-06-10 14:18:08 sbailliez Exp $
 */
public interface ILogSessionHome extends EJBHome {

   public static final String COMP_NAME="java:comp/env/ejb/LogSession";
   public static final String JNDI_NAME="LogSession";
    
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IRaAdminSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */

    ILogSessionRemote create() throws RemoteException, CreateException;

}

