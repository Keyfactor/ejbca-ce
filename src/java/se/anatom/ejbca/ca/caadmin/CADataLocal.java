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


/**
 * For docs, see CADataBean
 *
 * @version $Id: CADataLocal.java,v 1.2 2004-04-16 07:38:58 anatom Exp $
 **/

public interface CADataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getCAId();
    
    public String getName();
    public void setName(String name);

    public String getSubjectDN();
    
    public int getStatus();
    public void setStatus(int status);    
    
    public long getExpireTime();
    public void setExpireTime(long expiretime);    

    public CA getCA() throws java.io.UnsupportedEncodingException;
    public void setCA(CA ca) throws java.io.UnsupportedEncodingException;    
    
    
}

