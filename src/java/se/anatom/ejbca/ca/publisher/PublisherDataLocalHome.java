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
 
package se.anatom.ejbca.ca.publisher;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.util.Collection;

/**
 * For docs, see PublisherDataBean
 *
 * @version $Id: PublisherDataLocalHome.java,v 1.2 2004-04-16 07:38:55 anatom Exp $
 **/
public interface PublisherDataLocalHome extends javax.ejb.EJBLocalHome {

    public PublisherDataLocal create(Integer id, String name, BasePublisher publisher)
        throws CreateException;

    public PublisherDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public PublisherDataLocal findByName(String name)
        throws FinderException;
    

    public Collection findAll()
        throws FinderException;
}

