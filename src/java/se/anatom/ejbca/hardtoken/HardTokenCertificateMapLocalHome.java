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


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocalHome.java,v 1.5 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenCertificateMapLocalHome extends javax.ejb.EJBLocalHome {

    public HardTokenCertificateMapLocal create(String certificatefingerprint, String tokensn)
        throws CreateException;

    public HardTokenCertificateMapLocal findByPrimaryKey(String certificatefingerprint)
        throws FinderException;
    
    public Collection findByTokenSN(String tokensn)
        throws FinderException;    

    public Collection findAll()
        throws FinderException;
}

