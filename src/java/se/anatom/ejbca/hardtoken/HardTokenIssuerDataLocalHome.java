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
 
package se.anatom.ejbca.hardtoken;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocalHome.java,v 1.7 2004-04-16 07:38:56 anatom Exp $
 **/
public interface HardTokenIssuerDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenIssuerDataLocal create(Integer id, String alias, int admingroupid,  HardTokenIssuer issuerdata)
        throws CreateException;

    public HardTokenIssuerDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public HardTokenIssuerDataLocal findByAlias(String alias)
        throws FinderException;
       

    public Collection findAll()
        throws FinderException;
}

