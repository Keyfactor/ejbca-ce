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
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.5 2004-04-16 07:39:00 anatom Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IAuthenticationSessionRemote interface
     *
     * @throws CreateException
     */
    IAuthenticationSessionLocal create() throws CreateException;
}
