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

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;



/**
 * For docs, see CADataBean
 *
 * @version $Id: CADataLocalHome.java,v 1.2 2004-04-16 07:38:58 anatom Exp $
 **/

public interface CADataLocalHome extends javax.ejb.EJBLocalHome {

    public CADataLocal create(String subjectdn, String name, int status, CA ca)
        throws CreateException;

    public CADataLocal findByPrimaryKey(Integer caid)
        throws FinderException;

    public CADataLocal findByName(String name)
        throws FinderException;

    public Collection findAll()
        throws FinderException;
}

