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

package se.anatom.ejbca.ca.crl;


import javax.ejb.CreateException;
import javax.ejb.EJBLocalHome;


/**
 * Home interface for Create CRL session.
 *
 * @version $Id: ICreateCRLSessionLocalHome.java,v 1.3 2004-06-15 16:42:28 sbailliez Exp $
 */

public interface ICreateCRLSessionLocalHome extends EJBLocalHome {

    public static final String COMP_NAME="java:comp/env/ejb/CreateCRLSessionLocal";
    public static final String JNDI_NAME="CreateCRLSessionLocal";

    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICreateCRLSessionLocal interface
     *
     * @throws CreateException
     */
    ICreateCRLSessionLocal create() throws CreateException;
}
