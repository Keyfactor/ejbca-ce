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

import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocal.java,v 1.6 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public String getTokenSN();

    public String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
    public void setUsername(String username);

    public Date getCreateTime();

    public void setCreateTime(Date createtime);

    public Date getModifyTime();

    public void setModifyTime(Date modifytime);

    public int getTokenType();

    public void setTokenType(int tokentype);
    
    public String getSignificantIssuerDN();
    
    public void setSignificantIssuerDN(String significantissuerdn);    

    public HardToken getHardToken();

    public void setHardToken(HardToken tokendata);
}

