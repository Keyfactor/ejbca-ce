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

package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminEntityDataDataBean
 *
 * @version $Id: AdminEntityDataLocalHome.java,v 1.3 2004-06-08 13:17:48 sbailliez Exp $
 **/
public interface AdminEntityDataLocalHome extends javax.ejb.EJBLocalHome {

   public static final String COMP_NAME="java:comp/env/ejb/AdminEntityDataLocal";

    public AdminEntityDataLocal create(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue)
        throws CreateException;
    public AdminEntityDataLocal findByPrimaryKey(AdminEntityPK primarykey)
        throws FinderException;
}
