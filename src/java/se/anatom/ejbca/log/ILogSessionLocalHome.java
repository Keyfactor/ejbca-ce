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

import javax.ejb.CreateException;

/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionLocalHome.java,v 1.7 2004-06-10 14:10:06 sbailliez Exp $
 */
public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {

   public static final String COMP_NAME="java:comp/env/ejb/LogSessionLocal";
   public static final String JNDI_NAME="LogSessionLocal";    

    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ILogSessionRemote interface
     *
     * @throws CreateException
     */

    ILogSessionLocal create() throws CreateException;


}

