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

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;

import java.util.Collection;

/**
 * For docs, see HardTokenProfileDataBean
 *
 * @version $Id: HardTokenProfileDataLocalHome.java,v 1.2 2004-04-16 07:38:56 anatom Exp $
 **/
public interface HardTokenProfileDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenProfileDataLocal create(Integer id, String name, HardTokenProfile profile)
        throws CreateException;

    public HardTokenProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    public HardTokenProfileDataLocal findByName(String name)
        throws FinderException;
    

    public Collection findAll()
        throws FinderException;
}

