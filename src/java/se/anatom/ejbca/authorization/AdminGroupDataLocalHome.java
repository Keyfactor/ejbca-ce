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

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminGroupDataBean
 *
 * @version $Id: AdminGroupDataLocalHome.java,v 1.4 2004-06-08 13:17:48 sbailliez Exp $
 **/

public interface AdminGroupDataLocalHome extends javax.ejb.EJBLocalHome {

   public static final String COMP_NAME="java:comp/env/ejb/AdminGroupDataLocal";

    public AdminGroupDataLocal create(Integer pk, String admingroupname, int caid)
        throws CreateException;

    public AdminGroupDataLocal findByPrimaryKey(Integer pk)
        throws FinderException;

    public AdminGroupDataLocal findByGroupNameAndCAId(String groupname, int caid)
	    throws FinderException;

    public Collection findAll()
        throws FinderException;

}

