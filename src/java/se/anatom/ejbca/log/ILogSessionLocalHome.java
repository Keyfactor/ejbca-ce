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
 * @version $Id: ILogSessionLocalHome.java,v 1.6 2004-06-10 12:35:05 sbailliez Exp $
 */
public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ILogSessionRemote interface
     *
     * @throws CreateException
     */

    ILogSessionLocal create() throws CreateException;


}

