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


/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocal.java,v 1.6 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenIssuerDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getAlias();

    public void setAlias(String alias);
    
    public int getAdminGroupId();
    
    public void setAdminGroupId(int admingroupid);
   
    public HardTokenIssuer getHardTokenIssuer();

    public void setHardTokenIssuer(HardTokenIssuer issuerdata);
}

