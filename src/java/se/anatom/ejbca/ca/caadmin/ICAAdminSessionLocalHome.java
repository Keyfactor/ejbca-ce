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
 

package se.anatom.ejbca.ca.caadmin;

import javax.ejb.CreateException;

/**
 * @version $Id: ICAAdminSessionLocalHome.java,v 1.2 2004-04-16 07:38:58 anatom Exp $
 */
public interface ICAAdminSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ICAAdminSessionLocal interface
     */
    ICAAdminSessionLocal create() throws CreateException;
}
