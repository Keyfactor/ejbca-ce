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

import javax.ejb.CreateException;


/**
 * Local home for authentication session
 *
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.6 2004-06-15 16:42:30 sbailliez Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {

   public static final String COMP_NAME="java:comp/env/ejb/AuthenticationSessionLocal";
   public static final String JNDI_NAME="AuthenticationSessionLocal";
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IAuthenticationSessionRemote interface
     *
     * @throws CreateException
     */
    IAuthenticationSessionLocal create() throws CreateException;
}
