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


/**
 * For docs, see AdminEntityDataBean
 *
 * @version $Id: AdminEntityDataLocal.java,v 1.2 2004-04-16 07:38:57 anatom Exp $
 **/

public interface AdminEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public int getMatchWith();
    public int getMatchType();
    public String  getMatchValue();

    public AdminEntity getAdminEntity(int caid);

}

