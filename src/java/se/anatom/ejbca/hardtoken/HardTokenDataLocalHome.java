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
import java.util.Collection;
import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocalHome.java,v 1.5 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenDataLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenDataLocal create(String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HardToken tokendata)
        throws CreateException;

    public HardTokenDataLocal findByPrimaryKey(String tokensn)
        throws FinderException;
    
    public Collection findByUsername(String username)
        throws FinderException;    

    public Collection findAll()
        throws FinderException;
}

